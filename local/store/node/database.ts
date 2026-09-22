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
 * point. A kernel file lock serializes state transactions across processes.
 * Other independent collections remain encrypted JSON records.
 *
 * All sensitive data encrypted before storage.
 */

import { access, mkdir, readFile, readdir, rm, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import { receivedContentKey, parseReceivedContent } from '../received-content';
import type { ReceivedContent } from '../../../types';
import { resolveSignalProtocolLogger, type Logger } from '../../../logger';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';
import { encryptRecord, decryptRecord, type EncryptedRecord } from './database-encryption';
import { getNodeDatabaseKeyManager, NODE_DATABASE_RESET_FILE } from './database-key';
import { withNodeDatabaseLock } from './database-lock';
import {
  commitNodeDatabaseFile,
  isNodeDatabaseDataEntry,
  isNodeDatabaseRecord,
  syncNodeDatabaseDirectory,
} from './database-file-commit';
import type { KyberPreKey } from '../../../keys';
import type { IdentityType } from '../../../keys/types';
import {
  createKyberPreKeyState,
  createKyberPreKeyInstanceId,
  getCurrentKyberPreKey,
  getRetainedKyberPreKey,
  retainKyberPreKey,
  type KyberPreKeyUse,
  type RetainedKyberPreKey,
  type StoredKyberPreKeyState,
  recordKyberPreKeyUse,
  recordKyberPreKeyUseById,
} from '../kyber-prekey-lifecycle';

/**
 * Default data directory
 */
export {};
const DEFAULT_DATA_DIR = join(homedir(), '.config', 'open-e2ee', 'signal-protocol');

export interface StoredNodeSession {
  userId: string;
  deviceId: number;
  serializedRecord: string;
}

/**
 * Group, user, and device identifiers each occupy their own key position.
 *
 * A single joined string key would let a delimiter inside any one component
 * shift the boundary between them, mapping two distinct senders onto one slot.
 */
export type NodeSenderKeyTree<T> = Record<string, Record<string, Record<string, T>>>;

/**
 * Group-messaging namespaces, mutated together so a rotation is one commit.
 *
 * The fields are `readonly` because a mutation callback receives a view onto
 * the state document, not the document. Replacing a field would update the
 * view and commit nothing. Edit the dictionaries in place.
 */
export interface NodeSenderKeyState<T> {
  /** groupId -> userId -> deviceId -> current state */
  readonly current: NodeSenderKeyTree<T>;
  /** groupId -> userId -> deviceId -> [current, ...previous] */
  readonly records: NodeSenderKeyTree<T[]>;
  /** groupId -> senderId -> deviceId -> chainIndex -> skipped message key */
  readonly skipped: Record<string, NodeSenderKeyTree<unknown>>;
}

/** SESAME device state and the sessions it owns, mutated as one unit. */
export interface NodeSesameState<T> {
  readonly users: Record<string, T>;
  readonly sessions: Record<string, StoredNodeSession>;
}

interface NodeAtomicSecurityState {
  version: 2;
  contacts: Record<string, unknown>;
  ecOneTimePreKeys: Record<string, unknown[]>;
  kemOneTimePreKeys: Record<string, unknown[]>;
  sessions: Record<string, StoredNodeSession>;
  /** SESAME user records, serialized by the adapter (Maps and byte arrays flattened). */
  sesameUsers: Record<string, unknown>;
  senderKeys: NodeSenderKeyTree<unknown>;
  senderKeyRecords: NodeSenderKeyTree<unknown[]>;
  skippedSenderKeys: Record<string, NodeSenderKeyTree<unknown>>;
  /** sessionId -> client timestamp -> MessageRecord */
  messageRecords: Record<string, Record<string, unknown>>;
  metadata: Record<string, string>;
  registrationIds: Record<string, number>;
  kyberPreKeyStates: Record<string, StoredKyberPreKeyState>;
}

function emptyDictionary<T>(): T {
  return Object.create(null) as T;
}

function createEmptySecurityState(): NodeAtomicSecurityState {
  return {
    version: 2,
    contacts: emptyDictionary(),
    ecOneTimePreKeys: emptyDictionary(),
    kemOneTimePreKeys: emptyDictionary(),
    sessions: emptyDictionary(),
    sesameUsers: emptyDictionary(),
    senderKeys: emptyDictionary(),
    senderKeyRecords: emptyDictionary(),
    skippedSenderKeys: emptyDictionary(),
    messageRecords: emptyDictionary(),
    metadata: emptyDictionary(),
    registrationIds: emptyDictionary(),
    kyberPreKeyStates: emptyDictionary(),
  };
}

/**
 * Rebuild a decoded dictionary with a null prototype, `depth` levels down.
 *
 * `JSON.parse` produces ordinary objects, on which `__proto__` and
 * `constructor` are not plain data keys: assigning to them either invokes an
 * inherited setter or is silently dropped. Every dictionary here is keyed by
 * identifiers the application supplies: user, group, device, session, and
 * metadata names. Each level is therefore rebuilt before it is indexed.
 */
function toNullPrototype<T>(value: unknown, depth: number): T {
  const source = (value ?? {}) as Record<string, unknown>;
  const result = emptyDictionary<Record<string, unknown>>();
  for (const key of Object.keys(source)) {
    result[key] = depth > 1 ? toNullPrototype(source[key], depth - 1) : source[key];
  }
  return result as T;
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
  private readonly logger: Required<Logger>;
  private securityStateMutation: Promise<void> = Promise.resolve();

  /**
   * Create a new NodeEncryptedDatabase instance
   *
   * @param dataDir Optional data directory (defaults to ~/.config/signal)
   */
  constructor(dataDir: string = DEFAULT_DATA_DIR, providedLogger?: Logger) {
    this.dataDir = dataDir;
    this.sessionsDir = join(dataDir, 'sessions');
    this.securityStatePath = join(dataDir, 'protocol_security_state_v1.json');
    this.logger = resolveSignalProtocolLogger(providedLogger);
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
    this.initPromise = this._initialize().catch((error) => {
      this.initPromise = null;
      throw error;
    });
    return this.initPromise;
  }

  private async _initialize(): Promise<void> {
    try {
      const dbKeyManager = getNodeDatabaseKeyManager(this.dataDir);
      await dbKeyManager.withKey(async (key) => {
        await mkdir(this.sessionsDir, { recursive: true, mode: 0o700 });
        this.dbKey = key;
        await this.initializeAtomicSecurityState();
      }, true);
    } catch (error) {
      this.dbKey = null;
      throw new EncryptionError(
        'Failed to initialize encrypted database',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Initialize the database if it is not initialized yet
   */
  private async ensureInitialized(): Promise<void> {
    await this.initialize();
  }

  private async withCurrentKey<T>(operation: () => Promise<T>): Promise<T> {
    return getNodeDatabaseKeyManager(this.dataDir).withKey(async (key) => {
      if (!this.dbKey || !Buffer.from(key).equals(Buffer.from(this.dbKey))) {
        throw new Error(
          'Node database authority changed. Close and reopen the store before retrying.'
        );
      }
      return operation();
    });
  }

  /**
   * Direct pre-1.0 format reset. Contacts, one-time prekeys, and sessions now
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

  private assertSecurityState(
    value: unknown
  ): asserts value is Partial<NodeAtomicSecurityState> & { version: 1 | 2 } {
    if (!value || typeof value !== 'object') throw new Error('Invalid Node security state');
    const state = value as Omit<Partial<NodeAtomicSecurityState>, 'version'> & { version?: number };
    if (
      (state.version !== 1 && state.version !== 2) ||
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
    const decoded = decryptRecord<unknown>(encrypted, this.dbKey!);
    this.assertSecurityState(decoded);
    // A version 1 document predates the SESAME, group, message-record, and
    // metadata namespaces. It is widened here rather than reset. Discarding it
    // would drop pinned contact identities, and an unpinned contact is one
    // whose next identity change goes undetected.
    return {
      version: 2,
      contacts: toNullPrototype(decoded.contacts, 1),
      ecOneTimePreKeys: toNullPrototype(decoded.ecOneTimePreKeys, 1),
      kemOneTimePreKeys: toNullPrototype(decoded.kemOneTimePreKeys, 1),
      sessions: toNullPrototype(decoded.sessions, 1),
      sesameUsers: toNullPrototype(decoded.sesameUsers, 1),
      senderKeys: toNullPrototype(decoded.senderKeys, 3),
      senderKeyRecords: toNullPrototype(decoded.senderKeyRecords, 3),
      skippedSenderKeys: toNullPrototype(decoded.skippedSenderKeys, 4),
      messageRecords: toNullPrototype(decoded.messageRecords, 2),
      metadata: toNullPrototype(decoded.metadata, 1),
      registrationIds: toNullPrototype(decoded.registrationIds, 1),
      kyberPreKeyStates: toNullPrototype(decoded.kyberPreKeyStates, 1),
    };
  }

  private async writeSecurityStateFile(state: NodeAtomicSecurityState): Promise<void> {
    const encrypted = encryptRecord(state, this.dbKey!);
    try {
      await commitNodeDatabaseFile(this.securityStatePath, JSON.stringify(encrypted));
    } catch (error) {
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
    return this.withCurrentKey(() => this.readSecurityStateFile());
  }

  private async mutateSecurityState<T>(
    mutation: (state: NodeAtomicSecurityState) => T,
    commitWhen: (result: T) => boolean = () => true
  ): Promise<T> {
    await this.ensureInitialized();
    const operation = this.securityStateMutation.then(() =>
      this.withCurrentKey(async () => {
        const state = await this.readSecurityStateFile();
        const result = mutation(state);
        if (commitWhen(result)) await this.writeSecurityStateFile(state);
        return result;
      })
    );
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
    const name = `${collection}.json`;
    if (!isNodeDatabaseRecord(name)) throw new Error('Invalid Node database collection.');
    return join(this.dataDir, name);
  }

  // ============================================================================
  // Generic Collection Operations
  // ============================================================================

  /**
   * Read a collection from disk
   */
  private async readCollection<T>(collection: string): Promise<T[]> {
    await this.ensureInitialized();
    return this.withCurrentKey(async () => {
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
    });
  }

  /**
   * Write a collection to disk
   */
  private async writeCollection<T>(collection: string, data: T[]): Promise<void> {
    await this.ensureInitialized();
    return this.withCurrentKey(async () => {
      const filePath = this.getCollectionPath(collection);
      const encrypted = encryptRecord(data, this.dbKey!);

      try {
        await commitNodeDatabaseFile(filePath, JSON.stringify(encrypted));
      } catch (error) {
        throw new EncryptionError(
          `Failed to write collection: ${collection}`,
          EncryptionErrorCode.KEY_STORAGE_ERROR,
          { originalError: error as Error }
        );
      }
    });
  }

  /**
   * Delete a collection from disk
   */
  private async deleteCollection(collection: string): Promise<void> {
    await this.ensureInitialized();
    return this.withCurrentKey(async () => {
      const filePath = this.getCollectionPath(collection);

      try {
        await unlink(filePath);
        await syncNodeDatabaseDirectory(this.dataDir);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw new EncryptionError(
            `Failed to delete collection: ${collection}`,
            EncryptionErrorCode.KEY_STORAGE_ERROR,
            { originalError: error as Error }
          );
        }
      }
    });
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
      else state.ecOneTimePreKeys = emptyDictionary();
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

  async storeKyberPreKey(key: KyberPreKey, identityType: IdentityType = 'aci'): Promise<void> {
    const instanceId = await createKyberPreKeyInstanceId();
    await this.mutateSecurityState((state) => {
      const kyberState =
        state.kyberPreKeyStates[identityType] ??
        (state.kyberPreKeyStates[identityType] = createKyberPreKeyState());
      retainKyberPreKey(kyberState, key, identityType, Date.now(), instanceId);
    });
  }

  async getCurrentKyberPreKey(identityType: IdentityType = 'aci'): Promise<KyberPreKey | null> {
    const state = await this.readSecurityState();
    return getCurrentKyberPreKey(state.kyberPreKeyStates[identityType]);
  }

  async getKyberPreKeyById(
    id: number,
    identityType: IdentityType = 'aci'
  ): Promise<RetainedKyberPreKey | null> {
    const state = await this.readSecurityState();
    return getRetainedKyberPreKey(state.kyberPreKeyStates[identityType], id);
  }

  async deleteKyberPreKey(id: number, identityType: IdentityType = 'aci'): Promise<void> {
    await this.mutateSecurityState((state) => {
      const kyberState = state.kyberPreKeyStates[identityType];
      if (!kyberState) return;
      delete kyberState.instances[String(id)];
      if (kyberState.currentKeyId === id) kyberState.currentKeyId = null;
    });
  }

  async deleteAllKyberPreKeys(identityType?: string): Promise<void> {
    await this.mutateSecurityState((state) => {
      if (identityType) delete state.kyberPreKeyStates[identityType];
      else state.kyberPreKeyStates = emptyDictionary();
    });
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
      state.sessions = emptyDictionary();
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
    kemOneTimePreKeyId?: number,
    receivedContent?: ReceivedContent,
    kyberPreKeyUse?: KyberPreKeyUse
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
      if (kyberPreKeyUse) {
        recordKyberPreKeyUse(
          state.kyberPreKeyStates[localIdentityType],
          localIdentityType as IdentityType,
          kyberPreKeyUse
        );
      }
      state.contacts[contactKey] = contactMutation(
        (state.contacts[contactKey] as T | undefined) ?? null
      );
      state.sessions[sessionId] = { userId, deviceId, serializedRecord };
      if (receivedContent)
        state.metadata[receivedContentKey(receivedContent.id)] = JSON.stringify(receivedContent);
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
  // SESAME Device State
  //
  // Device records and the sessions they own are one mutation domain. A device
  // record naming a session that is not in `sessions`, or the reverse, is a
  // divergence no later read can repair. Both therefore move under one commit.
  // ============================================================================

  async readSesameState<T>(): Promise<NodeSesameState<T>> {
    const state = await this.readSecurityState();
    return { users: state.sesameUsers as Record<string, T>, sessions: state.sessions };
  }

  /** Drop every session and every SESAME device record in one commit. */
  async clearSesameState(): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.sessions = emptyDictionary();
      state.sesameUsers = emptyDictionary();
    });
  }

  async mutateSesameState<T, R>(mutation: (state: NodeSesameState<T>) => R): Promise<R> {
    return await this.mutateSecurityState((state) =>
      mutation({ users: state.sesameUsers as Record<string, T>, sessions: state.sessions })
    );
  }

  // ============================================================================
  // Sender Keys (Group Messaging)
  // ============================================================================

  async readSenderKeyState<T>(): Promise<NodeSenderKeyState<T>> {
    const state = await this.readSecurityState();
    return {
      current: state.senderKeys as NodeSenderKeyTree<T>,
      records: state.senderKeyRecords as NodeSenderKeyTree<T[]>,
      skipped: state.skippedSenderKeys,
    };
  }

  /**
   * Atomically update the group-messaging namespaces.
   *
   * A rotation writes the new current state and the retained previous states
   * together. A crash between them would leave a sender key whose in-flight
   * messages can no longer be resolved.
   */
  async mutateSenderKeyState<T, R>(
    mutation: (state: NodeSenderKeyState<T>) => R,
    receivedContent?: ReceivedContent
  ): Promise<R> {
    return await this.mutateSecurityState((state) => {
      const result = mutation({
        current: state.senderKeys as NodeSenderKeyTree<T>,
        records: state.senderKeyRecords as NodeSenderKeyTree<T[]>,
        skipped: state.skippedSenderKeys,
      });
      if (receivedContent)
        state.metadata[receivedContentKey(receivedContent.id)] = JSON.stringify(receivedContent);
      return result;
    });
  }

  // ============================================================================
  // Message Records (SESAME Retry Support)
  // ============================================================================

  async readMessageRecords<T>(): Promise<Record<string, Record<string, T>>> {
    const state = await this.readSecurityState();
    return state.messageRecords as Record<string, Record<string, T>>;
  }

  async mutateMessageRecords<T, R>(
    mutation: (records: Record<string, Record<string, T>>) => R
  ): Promise<R> {
    return await this.mutateSecurityState((state) =>
      mutation(state.messageRecords as Record<string, Record<string, T>>)
    );
  }

  // ============================================================================
  // Metadata, Registration IDs, and Kyber Usage
  // ============================================================================

  async getMetadataValue(key: string): Promise<string | null> {
    const state = await this.readSecurityState();
    return state.metadata[key] ?? null;
  }

  async setMetadataValue(key: string, value: string): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.metadata[key] = value;
    });
  }

  async deleteMetadataValue(key: string): Promise<void> {
    await this.mutateSecurityState((state) => {
      delete state.metadata[key];
    });
  }

  async deleteExpiredReceivedContent(before: number): Promise<number> {
    return this.mutateSecurityState((state) => {
      let count = 0;
      const prefix = receivedContentKey('');
      for (const [key, value] of Object.entries(state.metadata)) {
        if (!key.startsWith(prefix)) continue;
        if (parseReceivedContent(value, key.slice(prefix.length)).receivedAt < before) {
          delete state.metadata[key];
          count++;
        }
      }
      return count;
    });
  }

  async compareAndSetMetadataValue(
    key: string,
    expected: string | null,
    value: string | null
  ): Promise<boolean> {
    return this.mutateSecurityState(
      (state) => {
        if ((state.metadata[key] ?? null) !== expected) return false;
        if (value === null) delete state.metadata[key];
        else state.metadata[key] = value;
        return true;
      },
      (changed) => changed
    );
  }

  async getRegistrationId(identityType: string): Promise<number> {
    const state = await this.readSecurityState();
    return state.registrationIds[identityType] ?? 0;
  }

  async setRegistrationId(identityType: string, id: number): Promise<void> {
    await this.mutateSecurityState((state) => {
      state.registrationIds[identityType] = id;
    });
  }

  async markKyberPreKeyUsed(
    identityType: IdentityType,
    usage: Omit<KyberPreKeyUse, 'kyberPreKeyInstanceId'>
  ): Promise<void> {
    await this.mutateSecurityState((state) => {
      recordKyberPreKeyUseById(state.kyberPreKeyStates[identityType], identityType, usage);
    });
  }

  // ============================================================================
  // Key Recovery (PQXDH §4.13 identifier-collision recovery)
  // ============================================================================

  async getEcSignedPreKeyMaxId(identityType: string = 'aci'): Promise<number> {
    const keys = await this.readCollection<{ keyId: number }>(`signed_prekeys_${identityType}`);
    return keys.reduce((max, key) => (key.keyId > max ? key.keyId : max), 0);
  }

  async getKyberPreKeyMaxId(identityType: string = 'aci'): Promise<number> {
    const state = await this.readSecurityState();
    const instances = state.kyberPreKeyStates[identityType]?.instances ?? {};
    return Object.keys(instances).reduce((max, id) => Math.max(max, Number(id)), 0);
  }

  async deleteAllPreKeys(
    identityType: string = 'aci'
  ): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }> {
    const signedPreKeys = await this.readCollection<unknown>(`signed_prekeys_${identityType}`);

    const oneTimeCounts = await this.mutateSecurityState((state) => {
      const ec = (state.ecOneTimePreKeys[identityType] ?? []).length;
      const kem = (state.kemOneTimePreKeys[identityType] ?? []).length;
      const kyber = Object.keys(state.kyberPreKeyStates[identityType]?.instances ?? {}).length;
      delete state.ecOneTimePreKeys[identityType];
      delete state.kemOneTimePreKeys[identityType];
      delete state.kyberPreKeyStates[identityType];
      return { ec, kem, kyber };
    });

    await Promise.all([this.deleteCollection(`signed_prekeys_${identityType}`)]);

    return {
      ecSignedPreKeys: signedPreKeys.length,
      ecOneTimePreKeys: oneTimeCounts.ec,
      kyberPreKeys: oneTimeCounts.kyber,
      kemOneTimePreKeys: oneTimeCounts.kem,
    };
  }

  async getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    const state = await this.readSecurityState();
    const [signedAci, signedPni] = await Promise.all([
      this.readCollection(`signed_prekeys_aci`).then((keys) => keys.length),
      this.readCollection(`signed_prekeys_pni`).then((keys) => keys.length),
    ]);

    const total = (collection: Record<string, unknown[]>): number =>
      Object.values(collection).reduce((count, keys) => count + keys.length, 0);

    return {
      sessions: Object.keys(state.sessions).length,
      ecSignedPreKeys: signedAci + signedPni,
      ecOneTimePreKeys: total(state.ecOneTimePreKeys),
      kyberPreKeys: Object.values(state.kyberPreKeyStates).reduce(
        (count, kyberState) => count + Object.keys(kyberState.instances).length,
        0
      ),
      kemOneTimePreKeys: total(state.kemOneTimePreKeys),
      users: Object.keys(state.sesameUsers).length,
    };
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
    const [identityAci, identityPni, signedAci, signedPni] = await Promise.all([
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
    ]);

    return {
      identityKeys: identityAci + identityPni,
      signedPreKeys: signedAci + signedPni,
      oneTimePreKeys: Object.values(securityState.ecOneTimePreKeys).reduce(
        (count, keys) => count + keys.length,
        0
      ),
      kyberPreKeys: Object.values(securityState.kyberPreKeyStates).reduce(
        (count, kyberState) => count + Object.keys(kyberState.instances).length,
        0
      ),
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
    await this.initPromise?.catch(() => undefined);
    await this.securityStateMutation;
    this.dbKey = null;
    this.initPromise = null;
  }

  /**
   * Delete entire database (⚠️ DANGEROUS)
   *
   * Only for controlled local reset or factory reset.
   * This method is safe to call even if database does not exist.
   *
   * @returns true if database was deleted, false if it did not exist
   */
  async deleteDatabase(): Promise<boolean> {
    await this.initPromise?.catch(() => undefined);
    await this.securityStateMutation;
    return withNodeDatabaseLock(this.dataDir, async () => {
      const entries = (await readdir(this.dataDir)).filter(isNodeDatabaseDataEntry);
      if (entries.length === 0) return false;
      if (this.dbKey && !entries.includes(NODE_DATABASE_RESET_FILE)) {
        const key = await readFile(join(this.dataDir, 'db.key'));
        if (!key.equals(Buffer.from(this.dbKey))) {
          throw new Error('Node database authority changed. Refusing reset from a stale handle.');
        }
      }
      const marker = join(this.dataDir, NODE_DATABASE_RESET_FILE);
      await commitNodeDatabaseFile(marker, 'reset');
      for (const entry of entries) {
        if (entry !== NODE_DATABASE_RESET_FILE)
          await rm(join(this.dataDir, entry), { recursive: true, force: true });
      }
      await syncNodeDatabaseDirectory(this.dataDir);
      await unlink(marker);
      await syncNodeDatabaseDirectory(this.dataDir);
      this.dbKey = null;
      this.initPromise = null;
      this.logger.info('[NodeEncryptedDatabase] Database reset complete');
      return true;
    });
  }
}

/**
 * Singleton instance
 */
const encryptedDatabaseInstances = new Map<string, NodeEncryptedDatabase>();

/**
 * Get singleton NodeEncryptedDatabase instance
 *
 * @param dataDir Optional custom data directory
 */
export function getNodeEncryptedDatabase(dataDir?: string): NodeEncryptedDatabase {
  const path = resolve(dataDir ?? DEFAULT_DATA_DIR);
  let instance = encryptedDatabaseInstances.get(path);
  if (!instance) {
    instance = new NodeEncryptedDatabase(path);
    encryptedDatabaseInstances.set(path, instance);
  }
  return instance;
}

/**
 * Reset the singleton for controlled local teardown.
 */
export async function resetNodeEncryptedDatabase(): Promise<void> {
  await Promise.all([...encryptedDatabaseInstances.values()].map((instance) => instance.close()));
  encryptedDatabaseInstances.clear();
}
