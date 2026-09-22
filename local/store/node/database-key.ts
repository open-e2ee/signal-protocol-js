/**
 * Node.js Database Key Manager
 *
 * Manages the database encryption key for Node.js applications.
 *
 * Layer 1 (Secure Storage): Single 32-byte database encryption key
 * Layer 2 (Encrypted Files): All Signal Protocol keys, encrypted with the database key
 *
 * Security Properties:
 * - Database key stored with 0600 permissions (owner read/write only)
 * - Key generated once on first initialization
 * - All large keys (Kyber, etc.) stored in encrypted files
 *
 * Storage Strategy:
 * - Primary: Filesystem with strict owner-only permissions
 * - Optional: OS keychain via keytar (if available)
 */

import { randomBytes } from 'node:crypto';
import { access, readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import { withNodeDatabaseLock } from './database-lock';
import {
  clearPendingNodeDatabaseFiles,
  commitNodeDatabaseFile,
  syncNodeDatabaseDirectory,
} from './database-file-commit';

/**
 * Database encryption key size (AES-256)
 */
export {};
const DB_KEY_SIZE = 32; // 256 bits

/**
 * Default directory for Signal Protocol storage
 */
const DEFAULT_DATA_DIR = join(homedir(), '.config', 'open-e2ee', 'signal-protocol');

/**
 * Filename for the database encryption key
 */
const DB_KEY_FILENAME = 'db.key';

/** A durable marker prevents access during an incomplete explicit reset. */
export const NODE_DATABASE_RESET_FILE = '.database.reset';

/**
 * Node.js Database Key Manager
 *
 * Handles generation, storage, and retrieval of the database encryption key.
 * This key encrypts and decrypts all Signal Protocol keys in storage.
 */
export class NodeDatabaseKeyManager {
  private cachedKey: Uint8Array | null = null;
  private readonly keyFilePath: string;

  constructor(private readonly dataDir: string = DEFAULT_DATA_DIR) {
    this.keyFilePath = join(dataDir, DB_KEY_FILENAME);
  }

  /**
   * Initialize the database encryption key
   *
   * Generates and stores a new 32-byte key if one does not exist.
   * Callers should run this once on app start.
   *
   * @returns true if the method generated a key, false if one already exists
   */
  async initialize(): Promise<boolean> {
    return withNodeDatabaseLock(this.dataDir, () => this.initializeLocked());
  }

  private async initializeLocked(): Promise<boolean> {
    try {
      await clearPendingNodeDatabaseFiles(this.dataDir);
      // Check if key already exists
      const existingKey = await this.readKeyLocked();
      if (existingKey) {
        return false;
      }

      try {
        await access(join(this.dataDir, 'protocol_security_state_v1.json'));
        throw new Error(
          'Node database key is missing. Restore the key or explicitly reset the store.'
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }

      // Generate cryptographically secure random 32-byte key
      const keyBytes = randomBytes(DB_KEY_SIZE);

      // Store in filesystem with secure permissions
      await commitNodeDatabaseFile(this.keyFilePath, keyBytes);

      // Cache the key
      this.cachedKey = new Uint8Array(keyBytes);

      return true;
    } catch (error) {
      throw new EncryptionError(
        'Failed to initialize database encryption key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get the database encryption key
   *
   * Rechecks the filesystem and reuses the cached key only when its bytes match.
   * Returns null if key does not exist (needs initialization).
   *
   * @returns Database encryption key or null
   */
  async getKey(): Promise<Uint8Array | null> {
    return withNodeDatabaseLock(this.dataDir, () => this.readKeyLocked());
  }

  /** @internal Holds authority through the caller's complete state transaction. */
  async withKey<T>(operation: (key: Uint8Array) => Promise<T>, initialize = false): Promise<T> {
    return withNodeDatabaseLock(this.dataDir, async () => {
      if (initialize) await this.initializeLocked();
      const key = await this.readKeyLocked();
      if (!key)
        throw new Error(
          'Node database key is missing. Restore the key or explicitly reset the store.'
        );
      return operation(key);
    });
  }

  private async readKeyLocked(): Promise<Uint8Array | null> {
    try {
      await access(join(this.dataDir, NODE_DATABASE_RESET_FILE));
      throw new Error(
        'Node database reset is incomplete. Repeat the explicit reset before opening the store.'
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    try {
      // Read key from file. A missing file surfaces as ENOENT below. A
      // separate access() pre-check would race against concurrent
      // creation or deletion of the key file.
      const keyBuffer = await readFile(this.keyFilePath);
      const keyBytes = new Uint8Array(keyBuffer);

      // Validate key size
      if (keyBytes.length !== DB_KEY_SIZE) {
        throw new Error(
          `Invalid database key size: expected ${DB_KEY_SIZE} bytes, got ${keyBytes.length}`
        );
      }

      // Recheck disk on each transaction so reset cannot leave a stale writer.
      if (this.cachedKey && Buffer.from(this.cachedKey).equals(keyBuffer)) return this.cachedKey;
      this.cachedKey = keyBytes;

      return keyBytes;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        this.cachedKey = null;
        return null;
      }
      throw new EncryptionError(
        'Failed to retrieve database encryption key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get the database encryption key (throws if not initialized)
   *
   * Convenience method that throws when the key is missing.
   * Use this when you expect the key to be initialized.
   *
   * @throws EncryptionError if key does not exist
   * @returns Database encryption key
   */
  async getKeyOrThrow(): Promise<Uint8Array> {
    const key = await this.getKey();
    if (!key) {
      throw new EncryptionError(
        'Database encryption key not initialized. Call initialize() first.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    return key;
  }

  /**
   * Check if database encryption key exists
   *
   * @returns true if key exists, false otherwise
   */
  async hasKey(): Promise<boolean> {
    try {
      const key = await this.getKey();
      return key !== null;
    } catch {
      return false;
    }
  }

  /**
   * Delete the database encryption key
   *
   * ⚠️ DANGEROUS: This will make all encrypted data
   * permanently unrecoverable. Only use for:
   * - Account deletion
   * - Factory reset
   * - Controlled local reset
   *
   * @returns true if the method deleted a key, false if none existed
   */
  async deleteKey(): Promise<boolean> {
    return withNodeDatabaseLock(this.dataDir, async () => {
      try {
        const exists = await this.readKeyLocked();
        if (!exists) {
          return false;
        }

        await unlink(this.keyFilePath);
        await syncNodeDatabaseDirectory(this.dataDir);

        // Clear cache
        this.cachedKey = null;

        return true;
      } catch (error) {
        throw new EncryptionError(
          'Failed to delete database encryption key',
          EncryptionErrorCode.KEY_STORAGE_ERROR,
          { originalError: error as Error }
        );
      }
    });
  }

  /**
   * Rotate the database encryption key
   *
   * Generates a new key and returns both old and new keys.
   * Caller is responsible for:
   * 1. Re-encrypting all storage with new key
   * 2. Storing new key
   * 3. Deleting old key
   *
   * @returns Object with oldKey and newKey
   */
  async rotateKey(): Promise<{ oldKey: Uint8Array; newKey: Uint8Array }> {
    try {
      // Get existing key
      const oldKey = await this.getKeyOrThrow();

      // Generate new key
      const newKeyBytes = new Uint8Array(randomBytes(DB_KEY_SIZE));

      return { oldKey, newKey: newKeyBytes };
    } catch (error) {
      throw new EncryptionError(
        'Failed to rotate database encryption key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Complete key rotation after re-encryption
   *
   * Stores the new key and clears cache.
   * Call this AFTER successfully re-encrypting all data.
   *
   * @param newKey The new database encryption key
   */
  async completeKeyRotation(newKey: Uint8Array): Promise<void> {
    return withNodeDatabaseLock(this.dataDir, async () => {
      try {
        // Validate key size
        if (newKey.length !== DB_KEY_SIZE) {
          throw new Error(`Invalid key size: expected ${DB_KEY_SIZE} bytes`);
        }

        // Store new key
        await this.readKeyLocked();
        await commitNodeDatabaseFile(this.keyFilePath, newKey);

        // Update cache
        this.cachedKey = newKey;
      } catch (error) {
        throw new EncryptionError(
          'Failed to complete database key rotation',
          EncryptionErrorCode.KEY_STORAGE_ERROR,
          { originalError: error as Error }
        );
      }
    });
  }

  /**
   * Clear cached key (security: minimize key in memory)
   *
   * Forces next getKey() to read from filesystem.
   * Call this when application exits.
   */
  clearCache(): void {
    this.cachedKey = null;
  }

  /**
   * Get the key file path for diagnostics.
   */
  getKeyFilePath(): string {
    return this.keyFilePath;
  }
}

/**
 * Singleton instance
 */
let dbKeyManagerInstance: NodeDatabaseKeyManager | null = null;

/**
 * Get singleton NodeDatabaseKeyManager instance
 *
 * @param dataDir Optional custom data directory
 */
export function getNodeDatabaseKeyManager(dataDir?: string): NodeDatabaseKeyManager {
  if (
    !dbKeyManagerInstance ||
    (dataDir && dbKeyManagerInstance.getKeyFilePath() !== join(dataDir, DB_KEY_FILENAME))
  ) {
    dbKeyManagerInstance = new NodeDatabaseKeyManager(dataDir);
  }
  return dbKeyManagerInstance;
}

/**
 * Reset the singleton for controlled local teardown.
 */
export function resetNodeDatabaseKeyManager(): void {
  if (dbKeyManagerInstance) {
    dbKeyManagerInstance.clearCache();
  }
  dbKeyManagerInstance = null;
}
