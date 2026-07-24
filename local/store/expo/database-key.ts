/**
 * Database Key Manager
 *
 * Manages the single database encryption key stored through the configured
 * local secret vault. The default Expo vault uses `expo-secure-store`.
 *
 * Layer 1 (secret vault): Single 32-byte database encryption key
 * Layer 2 (SQLCipher): Full-database encryption configured by the host app
 *
 * Security Properties:
 * - Key generated once on first initialization
 * - Key custody follows the configured secret-vault implementation
 * - Key is loaded into application memory only when SQLCipher setup requires it
 * - Protocol records remain in the application-owned encrypted database
 *
 * See docs/E2EE.md for architecture details.
 */

import * as Crypto from 'expo-crypto';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import { resolveSignalLogger, type ILogger } from '../../../logger';
import type { ISignalLocalSecretVault } from '../../../types/api';
import { bytesToHex } from '../../../encoding';
import { ExpoSecureStoreSignalSecretVault } from '../../vault/expo-secure-store';

/**
 * Secret-vault identifier for the database encryption key
 */
const DB_ENCRYPTION_KEY_ID = 'signal_db_encryption_key';

/**
 * Database encryption key size (AES-256)
 */
const DB_KEY_SIZE = 32; // 256 bits

function rootCauseMessage(error: unknown): string {
  let current: unknown = error;
  while (current instanceof EncryptionError && current.originalError) {
    current = current.originalError;
  }

  if (current instanceof Error && current.message) {
    return current.message;
  }

  return String(current);
}

function storageErrorMessage(operation: string, error: unknown): string {
  return `${operation}: ${rootCauseMessage(error)}`;
}

/**
 * Database Key Manager
 *
 * Handles generation, storage, and retrieval of the database encryption key.
 * This key is used to encrypt/decrypt all Signal Protocol keys in the SQLite database.
 */
export class DatabaseKeyManager {
  private cachedKey: Uint8Array | null = null;
  private initPromise: Promise<boolean> | null = null;
  private logger: Required<ILogger>;
  private secretVault: ISignalLocalSecretVault;

  constructor(
    secretVault: ISignalLocalSecretVault = new ExpoSecureStoreSignalSecretVault(),
    providedLogger?: ILogger
  ) {
    this.secretVault = secretVault;
    this.logger = resolveSignalLogger(providedLogger);
  }

  setLogger(providedLogger?: ILogger): void {
    this.logger = resolveSignalLogger(providedLogger);
  }

  /**
   * Initialize the database encryption key
   *
   * Generates and stores a new 32-byte key if one doesn't exist.
   * This should be called once on app initialization.
   * Uses initPromise pattern to prevent race conditions from concurrent calls.
   *
   * @returns true if key was generated, false if already exists
   */
  async initialize(): Promise<boolean> {
    if (this.initPromise) {
      return this.initPromise;
    }
    this.initPromise = this._initialize();
    return this.initPromise;
  }

  private async _initialize(): Promise<boolean> {
    try {
      // Check if key already exists
      const existingKey = await this.getKey();
      if (existingKey) {
        this.logger.info('[DatabaseKeyManager] Database encryption key already exists');
        return false;
      }

      this.logger.info('[DatabaseKeyManager] Generating new database encryption key...');

      // Generate cryptographically secure random 32-byte key
      const keyBytes = await Crypto.getRandomBytesAsync(DB_KEY_SIZE);

      await this.secretVault.setSecret(DB_ENCRYPTION_KEY_ID, keyBytes);

      // Cache the key
      this.cachedKey = keyBytes;

      this.logger.info('[DatabaseKeyManager] Database encryption key generated and stored');
      return true;
    } catch (error) {
      this.initPromise = null; // Allow retry on failure
      throw new EncryptionError(
        storageErrorMessage('Failed to initialize database encryption key', error),
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get the database encryption key
   *
   * Retrieves the key from the configured secret vault (or cache if available).
   * Returns null if key doesn't exist (needs initialization).
   *
   * @returns Database encryption key or null
   */
  async getKey(): Promise<Uint8Array | null> {
    try {
      // Return cached key if available
      if (this.cachedKey) {
        return this.cachedKey;
      }

      const keyBytes = await this.secretVault.getSecret(DB_ENCRYPTION_KEY_ID);
      if (!keyBytes) {
        return null;
      }

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
      throw new EncryptionError(
        storageErrorMessage('Failed to retrieve database encryption key', error),
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get the database encryption key (throws if not initialized)
   *
   * Convenience method that ensures the key exists.
   * Use this when you expect the key to be initialized.
   *
   * @throws EncryptionError if key doesn't exist
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
   * Get the database password for SQLCipher
   *
   * Returns the database encryption key as a hex string for use with
   * SQLCipher's PRAGMA key. Uses hex format (x'...') for full 256-bit entropy.
   *
   * @throws EncryptionError if key doesn't exist
   * @returns SQLCipher-compatible password string
   */
  async getPassword(): Promise<string> {
    const key = await this.getKeyOrThrow();
    // Convert to hex string for SQLCipher (x'...' format gives full 256-bit entropy)
    const hexKey = bytesToHex(key);
    return `x'${hexKey}'`;
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
    } catch (error) {
      // If error retrieving, treat as not existing
      this.logger.error('Error checking database key existence', {
        category: 'DatabaseKeyManager',
        error: error as Error,
      });
      return false;
    }
  }

  /**
   * Delete the database encryption key
   *
   * Deleting the active key makes the local SQLCipher database unreadable
   * through this key path. The application remains responsible for database
   * copies, backups, and coordinated account-reset cleanup. Only use for:
   * - Account deletion
   * - Factory reset
   * - Controlled local reset
   *
   * @returns true if key was deleted, false if didn't exist
   */
  async deleteKey(): Promise<boolean> {
    try {
      const exists = await this.hasKey();
      if (!exists) {
        return false;
      }

      await this.secretVault.deleteSecret(DB_ENCRYPTION_KEY_ID);

      // Clear cache
      this.cachedKey = null;

      this.logger.info('[DatabaseKeyManager] Database encryption key deleted');
      return true;
    } catch (error) {
      throw new EncryptionError(
        storageErrorMessage('Failed to delete database encryption key', error),
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
   * 1. Rekeying the SQLCipher database with the new key
   * 2. Storing the new key in the configured secret vault
   * 3. Deleting old key
   *
   * @returns Object with oldKey and newKey
   */
  async rotateKey(): Promise<{ oldKey: Uint8Array; newKey: Uint8Array }> {
    try {
      // Get existing key
      const oldKey = await this.getKeyOrThrow();

      // Generate new key
      const newKeyBytes = await Crypto.getRandomBytesAsync(DB_KEY_SIZE);

      // Zero old cached key before replacing with new key
      if (this.cachedKey) {
        this.cachedKey.fill(0);
      }
      this.cachedKey = null;

      this.logger.info('[DatabaseKeyManager] Database encryption key rotation initiated');

      return { oldKey, newKey: newKeyBytes };
    } catch (error) {
      throw new EncryptionError(
        storageErrorMessage('Failed to rotate database encryption key', error),
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Complete key rotation after re-encryption
   *
   * Stores the new key in the configured secret vault and updates the cache.
   * Call this only after the application has successfully rekeyed SQLCipher.
   *
   * @param newKey The new database encryption key
   */
  async completeKeyRotation(newKey: Uint8Array): Promise<void> {
    try {
      // Validate key size
      if (newKey.length !== DB_KEY_SIZE) {
        throw new Error(`Invalid key size: expected ${DB_KEY_SIZE} bytes`);
      }

      await this.secretVault.setSecret(DB_ENCRYPTION_KEY_ID, newKey);

      // Update cache
      this.cachedKey = newKey;

      this.logger.info('[DatabaseKeyManager] Key rotation complete');
    } catch (error) {
      throw new EncryptionError(
        storageErrorMessage('Failed to complete database key rotation', error),
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Clear cached key (security: minimize key in memory)
   *
   * Forces next getKey() to read from the configured secret vault.
   * Call this when app goes to background.
   */
  clearCache(): void {
    if (this.cachedKey) {
      this.cachedKey.fill(0);
    }
    this.cachedKey = null;
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================
}

/**
 * Singleton instance
 */
let dbKeyManagerInstance: DatabaseKeyManager | null = null;

/**
 * Get singleton DatabaseKeyManager instance
 */
export function getDatabaseKeyManager(providedLogger?: ILogger): DatabaseKeyManager {
  if (!dbKeyManagerInstance) {
    dbKeyManagerInstance = new DatabaseKeyManager(undefined, providedLogger);
  } else if (providedLogger) {
    dbKeyManagerInstance.setLogger(providedLogger);
  }
  return dbKeyManagerInstance;
}

/**
 * Reset the singleton for controlled local teardown.
 */
export function resetDatabaseKeyManager(): void {
  if (dbKeyManagerInstance) {
    dbKeyManagerInstance.clearCache();
  }
  dbKeyManagerInstance = null;
}

/**
 * Clear cached database key from memory
 *
 * Security: Minimizes time sensitive key material stays in memory.
 * Call this when app goes to background to reduce attack surface.
 *
 * The key will be re-read from the configured secret vault on next access.
 * This is a no-op if the key manager hasn't been initialized.
 */
export function clearDatabaseKeyCache(): void {
  if (dbKeyManagerInstance) {
    dbKeyManagerInstance.clearCache();
  }
}
