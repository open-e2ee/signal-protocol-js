/**
 * Encrypted Filesystem Database for Node.js
 *
 * Provides encrypted JSON file storage with AES-256-GCM encryption.
 *
 * Layer 1: Single database encryption key in secure file (NodeDatabaseKeyManager)
 * Layer 2: All Signal Protocol keys in encrypted JSON files (this file)
 *
 * Security-critical mutable state (contact trust, one-time prekeys, and
 * sessions) is committed through one encrypted, versioned state file. A
 * write-fsync/rename/directory-fsync sequence provides a crash-durable commit
 * point, and an in-process mutation queue serializes compare-and-swap updates.
 * Other independent collections remain encrypted JSON records.
 *
 * All sensitive data encrypted before storage.
 */

import { access, mkdir, open, readFile, rename, rm, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import { resolveSignalLogger, type ILogger } from '../../../logger';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';
import { getErrorMessage } from '../../../utils/errors';
import { encryptRecord, decryptRecord, type EncryptedRecord } from './database-encryption';
import { getNodeDatabaseKeyManager } from './database-key';

/**
 * Default data directory
 */
export {};
const DEFAULT_DATA_DIR = join(homedir(), '.config', 'open-e2ee', 'signal-protocol');

/**
 * File permissions for encrypted data (0600 = owner read/write only)
 */
const SECURE_FILE_MODE = 0o600;

interface StoredNodeSession {
  userId: string;
  deviceId: number;
  serializedRecord: string;
}

interface NodeAtomicSecurityState {
  version: 1;
  contacts: Record<string, unknown>;
  ecOneTimePreKeys: Record<string, unknown[]>;
  kemOneTimePreKeys: Record<string, unknown[]>;
  sessions: Record<string, StoredNodeSession>;
}

function createEmptySecurityState(): NodeAtomicSecurityState {
  return {
    version: 1,
    contacts: Object.create(null) as Record<string, unknown>,
    ecOneTimePreKeys: Object.create(null) as Record<string, unknown[]>,
    kemOneTimePreKeys: Object.create(null) as Record<string, unknown[]>,
    sessions: Object.create(null) as Record<string, StoredNodeSession>,
  };
}

/**
 * Node.js Encrypted Filesystem Database
 *
 * Handles all storage operations with automatic encryption/decryption.
 */
export class NodeEncryptedDatabase {
  private dbKey: Uint8Array | null = null;
  private initPromise: Promise<void> | null = null;
  private readonly dataDir: string;
  private readonly sessionsDir: string;
  private readonly securityStatePath: string;
  private readonly logger: Required<ILogger>;
  private securityStateMutation: Promise<void> = Promise.resolve();
  private atomicWriteCounter = 0;

  /**
   * Create a new NodeEncryptedDatabase instance
   *
   * @param dataDir Optional data directory (defaults to ~/.config/signal)
   */
  constructor(dataDir: string = DEFAULT_DATA_DIR, providedLogger?: ILogger) {
    this.dataDir = dataDir;
    this.sessionsDir = join(dataDir, 'sessions');
    this.securityStatePath = join(dataDir, 'protocol_security_state_v1.json');
    this.logger = resolveSignalLogger(providedLogger);
  }

  /**
   * Initialize the database
   *
   * Creates directory structure and retrieves database encryption key.
   * This is called automatically on first operation.
   */
  async initialize(): Promise<void> {
    // Return existing initialization promise if already initializing
    if (this.initPromise) {
      return this.initPromise;
    }

    // Create new initialization promise
    this.initPromise = this._initialize();
    return this.initPromise;
  }

  private async _initialize(): Promise<void> {
    try {
      // Create directory structure
      await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
      await mkdir(this.sessionsDir, { recursive: true, mode: 0o700 });

      // Get database encryption key
      const dbKeyManager = getNodeDatabaseKeyManager(this.dataDir);
      const hasKey = await dbKeyManager.hasKey();

      if (!hasKey) {
        // First initialization - generate database key
        await dbKeyManager.initialize();
      }

      this.dbKey = await dbKeyManager.getKeyOrThrow();
      await this.initializeAtomicSecurityState();
    } catch (error) {
      throw new EncryptionError(
        'Failed to initialize encrypted database',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Ensure database is initialized
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.dbKey) {
      await this.initialize();
    }
  }

  /**
   * Direct alpha-format reset. Contacts, one-time prekeys, and sessions now
   * share one encrypted document so security-sensitive multi-record commits are
   * one atomic filesystem replacement.
   */
  private async initializeAtomicSecurityState(): Promise<void> {
    try {
      await access(this.securityStatePath);
      await this.readSecurityStateFile();
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const legacyCollections = [
      'contact_identities_v1.json',
      'one_time_prekeys_aci.json',
      'one_time_prekeys_pni.json',
      'kem_one_time_prekeys_aci.json',
      'kem_one_time_prekeys_pni.json',
    ];
    await Promise.all(
      legacyCollections.map(async (filename) => {
        try {
          await unlink(join(this.dataDir, filename));
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      })
    );
    await rm(this.sessionsDir, { recursive: true, force: true });
    await mkdir(this.sessionsDir, { recursive: true, mode: 0o700 });
    await this.writeSecurityStateFile(createEmptySecurityState());
  }

  private assertSecurityState(value: unknown): asserts value is NodeAtomicSecurityState {
    if (!value || typeof value !== 'object') throw new Error('Invalid Node security state');
    const state = value as Partial<NodeAtomicSecurityState>;
    if (
      state.version !== 1 ||
      !state.contacts ||
      typeof state.contacts !== 'object' ||
      !state.ecOneTimePreKeys ||
      typeof state.ecOneTimePreKeys !== 'object' ||
      !state.kemOneTimePreKeys ||
      typeof state.kemOneTimePreKeys !== 'object' ||
      !state.sessions ||
      typeof state.sessions !== 'object'
    ) {
      throw new Error('Invalid Node security state structure');
    }
  }

  private async readSecurityStateFile(): Promise<NodeAtomicSecurityState> {
    const fileData = await readFile(this.securityStatePath, 'utf8');
    const encrypted = JSON.parse(fileData) as EncryptedRecord;
    const state = decryptRecord<unknown>(encrypted, this.dbKey!);
    this.assertSecurityState(state);
    // JSON.parse creates ordinary objects whose `__proto__`/`constructor`
    // names have special behavior. Normalize every attacker-influenced key
    // dictionary so arbitrary valid user IDs remain plain data keys.
    state.contacts = Object.assign(Object.create(null), state.contacts) as Record<
      string,
      unknown
    >;
    state.ecOneTimePreKeys = Object.assign(
      Object.create(null),
      state.ecOneTimePreKeys
    ) as Record<string, unknown[]>;
    state.kemOneTimePreKeys = Object.assign(
      Object.create(null),
      state.kemOneTimePreKeys
    ) as Record<string, unknown[]>;
    state.sessions = Object.assign(Object.create(null), state.sessions) as Record<
      string,
      StoredNodeSession
    >;
    return state;
  }

  private async writeSecurityStateFile(state: NodeAtomicSecurityState): Promise<void> {
    const encrypted = encryptRecord(state, this.dbKey!);
    const tempPath = `${this.securityStatePath}.${process.pid}.${this.atomicWriteCounter++}.tmp`;
    try {
      await writeFile(tempPath, JSON.stringify(encrypted), {
        mode: SECURE_FILE_MODE,
        encoding: 'utf8',
      });
      const handle = await open(tempPath, 'r');
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tempPath, this.securityStatePath);
      // POSIX rename is atomic, but the containing directory must also be
      // synchronized for the new directory entry to survive sudden power loss.
      // Windows does not support opening directories this way.
      if (process.platform !== 'win32') {
        const directoryHandle = await open(this.dataDir, 'r');
        try {
          await directoryHandle.sync();
        } finally {
          await directoryHandle.close();
        }
      }
    } catch (error) {
      await unlink(tempPath).catch(() => undefined);
      throw new EncryptionError(
        'Failed to atomically write Node protocol security state',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  private async readSecurityState(): Promise<NodeAtomicSecurityState> {
    await this.ensureInitialized();
    await this.securityStateMutation;
    return await this.readSecurityStateFile();
  }

  private async mutateSecurityState<T>(
    mutation: (state: NodeAtomicSecurityState) => T
  ): Promise<T> {
    await this.ensureInitialized();
    const operation = this.securityStateMutation.then(async () => {
      const state = await this.readSecurityStateFile();
      const result = mutation(state);
      await this.writeSecurityStateFile(state);
      return result;
    });
    this.securityStateMutation = operation.then(
      () => undefined,
      () => undefined
    );
    return await operation;
  }

  /**
   * Get file path for a collection
   */
  private getCollectionPath(collection: string): string {
    return join(this.dataDir, `${collection}.json`);
  }

  // ============================================================================
  // Generic Collection Operations
  // ============================================================================

  /**
   * Read a collection from disk
   */
  private async readCollection<T>(collection: string): Promise<T[]> {
    await this.ensureInitialized();

    const filePath = this.getCollectionPath(collection);

    try {
      const fileData = await readFile(filePath, 'utf8');
      const encrypted: EncryptedRecord = JSON.parse(fileData);
      return decryptRecord<T[]>(encrypted, this.dbKey!);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return [];
      }
      throw new EncryptionError(
        `Failed to read collection: ${collection}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Write a collection to disk
   */
  private async writeCollection<T>(collection: string, data: T[]): Promise<void> {
    await this.ensureInitialized();

    const filePath = this.getCollectionPath(collection);
    const encrypted = encryptRecord(data, this.dbKey!);

    try {
      await writeFile(filePath, JSON.stringify(encrypted), {
        mode: SECURE_FILE_MODE,
        encoding: 'utf8',
      });
    } catch (error) {
      throw new EncryptionError(
        `Failed to write collection: ${collection}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete a collection from disk
   */
  private async deleteCollection(collection: string): Promise<void> {
    const filePath = this.getCollectionPath(collection);

    try {
      await unlink(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new EncryptionError(
          `Failed to delete collection: ${collection}`,
          EncryptionErrorCode.KEY_STORAGE_ERROR,
          { originalError: error as Error }
        );
      }
    }
  }

  // ============================================================================
  // Identity Keys
  // ============================================================================

  async storeIdentityKey<T>(key: T, identityType: string = 'aci'): Promise<void> {
    const collection = `identity_keys_${identityType}`;
    await this.writeCollection(collection, [key]);
  }

  async getIdentityKey<T>(identityType: string = 'aci'): Promise<T | null> {
    const collection = `identity_keys_${identityType}`;
    const keys = await this.readCollection<T>(collection);
    return keys.length > 0 ? keys[0] : null;
  }

  async deleteIdentityKey(identityType?: string): Promise<void> {
    if (identityType) {
      await this.deleteCollection(`identity_keys_${identityType}`);
    } else {
      await this.deleteCollection('identity_keys_aci');
      await this.deleteCollection('identity_keys_pni');
    }
  }

  async getContactIdentity<T>(key: string): Promise<T | null> {
    const state = await this.readSecurityState();
    return (state.contacts[key] as T | undefined) ?? null;
  }

  async storeContactIdentity<T>(key: string, record: T): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.contacts[key] = record;
    });
  }

  async mutateContactIdentity<T>(key: string, mutation: (existing: T | null) => T): Promise<T> {
    return await this.mutateSecurityState((state) => {
      const replacement = mutation((state.contacts[key] as T | undefined) ?? null);
      state.contacts[key] = replacement;
      return replacement;
    });
  }

  async mutateContactIdentityAndDeleteSessions<T>(
    key: string,
    userId: string,
    mutation: (existing: T | null) => T
  ): Promise<T> {
    return await this.mutateSecurityState((state) => {
      const replacement = mutation((state.contacts[key] as T | undefined) ?? null);
      state.contacts[key] = replacement;
      for (const [sessionId, stored] of Object.entries(state.sessions)) {
        if (stored.userId === userId) delete state.sessions[sessionId];
      }
      return replacement;
    });
  }

  // ============================================================================
  // Signed PreKeys
  // Per X3DH Spec Section 4.4: Keep old signed prekeys for ~30 days
  // ============================================================================

  async storeEcSignedPreKey<T extends { keyId: number }>(
    key: T,
    identityType: string = 'aci'
  ): Promise<void> {
    const collection = `signed_prekeys_${identityType}`;
    const keys = await this.readCollection<T>(collection);
    // Update existing or add new (keep old prekeys for grace period)
    const existingIndex = keys.findIndex((k) => k.keyId === key.keyId);
    if (existingIndex >= 0) {
      keys[existingIndex] = key;
    } else {
      keys.push(key);
    }
    await this.writeCollection(collection, keys);
    await this.cleanupExpiredEcSignedPreKeys<T>(identityType);
  }

  async getEcSignedPreKey<T extends { keyId: number }>(
    keyId?: number,
    identityType: string = 'aci'
  ): Promise<T | null> {
    const collection = `signed_prekeys_${identityType}`;
    const keys = await this.readCollection<T>(collection);
    if (keys.length === 0) return null;

    if (keyId !== undefined) {
      // Look up by specific keyId
      return keys.find((k) => k.keyId === keyId) ?? null;
    }
    // Return the most recent (highest keyId)
    return keys.reduce((latest, current) => (current.keyId > latest.keyId ? current : latest));
  }

  async getAllEcSignedPreKeys<T>(identityType: string = 'aci'): Promise<T[]> {
    const collection = `signed_prekeys_${identityType}`;
    return await this.readCollection<T>(collection);
  }

  async removeEcSignedPreKey<T extends { keyId: number }>(
    keyId: number,
    identityType: string = 'aci'
  ): Promise<void> {
    const collection = `signed_prekeys_${identityType}`;
    const keys = await this.readCollection<T>(collection);
    await this.writeCollection(
      collection,
      keys.filter((k) => k.keyId !== keyId)
    );
  }

  async deleteSignedPreKey(identityType?: string): Promise<void> {
    if (identityType) {
      await this.deleteCollection(`signed_prekeys_${identityType}`);
    } else {
      await this.deleteCollection('signed_prekeys_aci');
      await this.deleteCollection('signed_prekeys_pni');
    }
  }

  private async cleanupExpiredEcSignedPreKeys<T extends { keyId: number; timestamp?: number }>(
    identityType: string = 'aci'
  ): Promise<void> {
    const collection = `signed_prekeys_${identityType}`;
    const keys = await this.readCollection<T>(collection);
    if (keys.length <= 1) return; // Keep at least one

    const cutoff = Date.now() - MAX_UNACKNOWLEDGED_SESSION_AGE_MS;
    const newest = keys.reduce((a, b) => (a.keyId > b.keyId ? a : b));

    const filtered = keys.filter(
      (k) => k.keyId === newest.keyId || (k.timestamp && k.timestamp > cutoff)
    );
    if (filtered.length < keys.length) {
      await this.writeCollection(collection, filtered);
    }
  }

  // ============================================================================
  // One-Time PreKeys
  // ============================================================================

  async storeEcOneTimePreKeys<T>(prekeys: T[], identityType: string = 'aci'): Promise<void> {
    await this.mutateSecurityState((state) => {
      const existing = (state.ecOneTimePreKeys[identityType] ?? []) as T[];
      state.ecOneTimePreKeys[identityType] = [...existing, ...prekeys];
    });
  }

  async getEcOneTimePreKeys<T>(identityType: string = 'aci'): Promise<T[]> {
    const state = await this.readSecurityState();
    return (state.ecOneTimePreKeys[identityType] ?? []) as T[];
  }

  async removeEcOneTimePreKey<T>(
    predicate: (key: T) => boolean,
    identityType: string = 'aci'
  ): Promise<void> {
    await this.mutateSecurityState((state) => {
      const keys = (state.ecOneTimePreKeys[identityType] ?? []) as T[];
      state.ecOneTimePreKeys[identityType] = keys.filter((key) => !predicate(key));
    });
  }

  async deleteOneTimePreKeys(identityType?: string): Promise<void> {
    await this.mutateSecurityState((state) => {
      if (identityType) delete state.ecOneTimePreKeys[identityType];
      else state.ecOneTimePreKeys = {};
    });
  }

  async storeKemOneTimePreKeys<T>(prekeys: T[], identityType: string = 'aci'): Promise<void> {
    await this.mutateSecurityState((state) => {
      const existing = (state.kemOneTimePreKeys[identityType] ?? []) as T[];
      state.kemOneTimePreKeys[identityType] = [...existing, ...prekeys];
    });
  }

  async getKemOneTimePreKeys<T>(identityType: string = 'aci'): Promise<T[]> {
    const state = await this.readSecurityState();
    return (state.kemOneTimePreKeys[identityType] ?? []) as T[];
  }

  async removeKemOneTimePreKey<T extends { keyId: number }>(
    keyId: number,
    identityType: string = 'aci'
  ): Promise<void> {
    await this.mutateSecurityState((state) => {
      const keys = (state.kemOneTimePreKeys[identityType] ?? []) as T[];
      state.kemOneTimePreKeys[identityType] = keys.filter((key) => key.keyId !== keyId);
    });
  }

  // ============================================================================
  // Kyber PreKeys
  // ============================================================================

  async storeKyberPreKey<T>(id: number, key: T, identityType: string = 'aci'): Promise<void> {
    const collection = `kyber_prekeys_${identityType}`;
    const keys = await this.readCollection<{ id: number; data: T }>(collection);
    // Replace existing key with same ID
    const filtered = keys.filter((k) => k.id !== id);
    filtered.push({ id, data: key });
    await this.writeCollection(collection, filtered);
  }

  async getKyberPreKey<T>(id: number, identityType: string = 'aci'): Promise<T | null> {
    const collection = `kyber_prekeys_${identityType}`;
    const keys = await this.readCollection<{ id: number; data: T }>(collection);
    const found = keys.find((k) => k.id === id);
    return found ? found.data : null;
  }

  async deleteKyberPreKey(id: number, identityType: string = 'aci'): Promise<void> {
    const collection = `kyber_prekeys_${identityType}`;
    const keys = await this.readCollection<{ id: number; data: unknown }>(collection);
    const filtered = keys.filter((k) => k.id !== id);
    await this.writeCollection(collection, filtered);
  }

  async deleteAllKyberPreKeys(identityType?: string): Promise<void> {
    if (identityType) {
      await this.deleteCollection(`kyber_prekeys_${identityType}`);
    } else {
      await this.deleteCollection('kyber_prekeys_aci');
      await this.deleteCollection('kyber_prekeys_pni');
    }
  }

  // ============================================================================
  // Sessions
  // ============================================================================

  async storeSession(
    sessionId: string,
    userId: string,
    deviceId: number,
    serializedRecord: string
  ): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.sessions[sessionId] = { userId, deviceId, serializedRecord };
    });
  }

  async getSession(sessionId: string): Promise<string | null> {
    const state = await this.readSecurityState();
    return state.sessions[sessionId]?.serializedRecord ?? null;
  }

  async getSessionsForUser(userId: string): Promise<string[]> {
    const state = await this.readSecurityState();
    return Object.values(state.sessions)
      .filter((session) => session.userId === userId)
      .map((session) => session.serializedRecord);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.mutateSecurityState((state) => {
      delete state.sessions[sessionId];
    });
  }

  async deleteAllSessions(): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.sessions = Object.create(null) as Record<string, StoredNodeSession>;
    });
  }

  async commitSessionTrust<T>(
    sessionId: string,
    userId: string,
    deviceId: number,
    serializedRecord: string,
    localIdentityType: string,
    contactKey: string,
    contactMutation: (existing: T | null) => T,
    oneTimePreKeyId?: number,
    kemOneTimePreKeyId?: number
  ): Promise<void> {
    await this.mutateSecurityState((state) => {
      if (
        oneTimePreKeyId !== undefined &&
        !((state.ecOneTimePreKeys[localIdentityType] ?? []) as Array<{ keyId: number }>).some(
          (key) => key.keyId === oneTimePreKeyId
        )
      ) {
        throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
      }
      if (
        kemOneTimePreKeyId !== undefined &&
        !((state.kemOneTimePreKeys[localIdentityType] ?? []) as Array<{ keyId: number }>).some(
          (key) => key.keyId === kemOneTimePreKeyId
        )
      ) {
        throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
      }
      state.contacts[contactKey] = contactMutation(
        (state.contacts[contactKey] as T | undefined) ?? null
      );
      state.sessions[sessionId] = { userId, deviceId, serializedRecord };
      if (oneTimePreKeyId !== undefined) {
        state.ecOneTimePreKeys[localIdentityType] = (
          (state.ecOneTimePreKeys[localIdentityType] ?? []) as Array<{ keyId: number }>
        ).filter((key) => key.keyId !== oneTimePreKeyId);
      }
      if (kemOneTimePreKeyId !== undefined) {
        state.kemOneTimePreKeys[localIdentityType] = (
          (state.kemOneTimePreKeys[localIdentityType] ?? []) as Array<{ keyId: number }>
        ).filter((key) => key.keyId !== kemOneTimePreKeyId);
      }
    });
  }

  // ============================================================================
  // Statistics
  // ============================================================================

  async getStats(): Promise<{
    identityKeys: number;
    signedPreKeys: number;
    oneTimePreKeys: number;
    kyberPreKeys: number;
    sessions: number;
  }> {
    await this.ensureInitialized();

    const securityState = await this.readSecurityState();
    const [
      identityAci,
      identityPni,
      signedAci,
      signedPni,
      kyberAci,
      kyberPni,
    ] = await Promise.all([
      this.readCollection('identity_keys_aci')
        .then((keys) => keys.length)
        .catch(() => 0),
      this.readCollection('identity_keys_pni')
        .then((keys) => keys.length)
        .catch(() => 0),
      this.readCollection('signed_prekeys_aci')
        .then((keys) => keys.length)
        .catch(() => 0),
      this.readCollection('signed_prekeys_pni')
        .then((keys) => keys.length)
        .catch(() => 0),
      this.readCollection<{ id: number; data: unknown }>('kyber_prekeys_aci')
        .then((keys) => keys.length)
        .catch(() => 0),
      this.readCollection<{ id: number; data: unknown }>('kyber_prekeys_pni')
        .then((keys) => keys.length)
        .catch(() => 0),
    ]);

    return {
      identityKeys: identityAci + identityPni,
      signedPreKeys: signedAci + signedPni,
      oneTimePreKeys: Object.values(securityState.ecOneTimePreKeys).reduce(
        (count, keys) => count + keys.length,
        0
      ),
      kyberPreKeys: kyberAci + kyberPni,
      sessions: Object.keys(securityState.sessions).length,
    };
  }

  // ============================================================================
  // Maintenance
  // ============================================================================

  /**
   * Close database (cleanup)
   */
  async close(): Promise<void> {
    this.dbKey = null;
    this.initPromise = null;
  }

  /**
   * Delete entire database (⚠️ DANGEROUS)
   *
   * Only for controlled local reset or factory reset.
   * This method is safe to call even if database doesn't exist.
   *
   * @returns true if database was deleted, false if it didn't exist
   */
  async deleteDatabase(): Promise<boolean> {
    try {
      // Close database connection if open
      await this.close();

      // Check if directory exists
      const exists = await this.databaseExists();
      if (!exists) {
        this.logger.info('[NodeEncryptedDatabase] Database does not exist, skipping deletion', {
          dataDir: this.dataDir,
        });
        return false;
      }

      // Delete the database directory recursively
      await rm(this.dataDir, { recursive: true, force: true });
      this.logger.info('[NodeEncryptedDatabase] Database deleted successfully', {
        dataDir: this.dataDir,
      });
      return true;
    } catch (error) {
      // Log error but don't throw - safe deletion should be idempotent
      this.logger.warn('[NodeEncryptedDatabase] Error during database deletion (safe to ignore)', {
        dataDir: this.dataDir,
        error: getErrorMessage(error),
      });
      return false;
    }
  }

  /**
   * Check if database directory exists
   *
   * @returns true if database directory exists on filesystem
   */
  private async databaseExists(): Promise<boolean> {
    try {
      await access(this.dataDir);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Singleton instance
 */
let encryptedDatabaseInstance: NodeEncryptedDatabase | null = null;

/**
 * Get singleton NodeEncryptedDatabase instance
 *
 * @param dataDir Optional custom data directory
 */
export function getNodeEncryptedDatabase(dataDir?: string): NodeEncryptedDatabase {
  if (!encryptedDatabaseInstance || (dataDir && encryptedDatabaseInstance['dataDir'] !== dataDir)) {
    encryptedDatabaseInstance = new NodeEncryptedDatabase(dataDir);
  }
  return encryptedDatabaseInstance;
}

/**
 * Reset the singleton for controlled local teardown.
 */
export async function resetNodeEncryptedDatabase(): Promise<void> {
  if (encryptedDatabaseInstance) {
    await encryptedDatabaseInstance.close();
  }
  encryptedDatabaseInstance = null;
}
