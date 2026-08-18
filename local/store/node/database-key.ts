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
import { mkdir, readFile, writeFile, unlink, chmod } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { EncryptionError, EncryptionErrorCode } from '../../../types';

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

/**
 * File permissions for the database key (0600 = owner read/write only)
 */
const SECURE_FILE_MODE = 0o600;

/**
 * Node.js Database Key Manager
 *
 * Handles generation, storage, and retrieval of the database encryption key.
 * This key encrypts and decrypts all Signal Protocol keys in storage.
 */
export class NodeDatabaseKeyManager {
  private cachedKey: Uint8Array | null = null;
  private readonly keyFilePath: string;

  constructor(dataDir: string = DEFAULT_DATA_DIR) {
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
    try {
      // Check if key already exists
      const existingKey = await this.getKey();
      if (existingKey) {
        return false;
      }

      // Create the directory if it is missing
      await mkdir(dirname(this.keyFilePath), { recursive: true, mode: 0o700 });

      // Generate cryptographically secure random 32-byte key
      const keyBytes = randomBytes(DB_KEY_SIZE);

      // Store in filesystem with secure permissions
      await writeFile(this.keyFilePath, keyBytes, { mode: SECURE_FILE_MODE });

      // Verify permissions were set correctly (some filesystems ignore mode)
      await chmod(this.keyFilePath, SECURE_FILE_MODE);

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
   * Retrieves the key from filesystem (or cache if available).
   * Returns null if key does not exist (needs initialization).
   *
   * @returns Database encryption key or null
   */
  async getKey(): Promise<Uint8Array | null> {
    try {
      // Return cached key if available
      if (this.cachedKey) {
        return this.cachedKey;
      }

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

      // Cache for future use
      this.cachedKey = keyBytes;

      return keyBytes;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
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
    try {
      const exists = await this.hasKey();
      if (!exists) {
        return false;
      }

      await unlink(this.keyFilePath);

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
    try {
      // Validate key size
      if (newKey.length !== DB_KEY_SIZE) {
        throw new Error(`Invalid key size: expected ${DB_KEY_SIZE} bytes`);
      }

      // Store new key
      await writeFile(this.keyFilePath, newKey, { mode: SECURE_FILE_MODE });

      // Verify permissions
      await chmod(this.keyFilePath, SECURE_FILE_MODE);

      // Update cache
      this.cachedKey = newKey;
    } catch (error) {
      throw new EncryptionError(
        'Failed to complete database key rotation',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
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
