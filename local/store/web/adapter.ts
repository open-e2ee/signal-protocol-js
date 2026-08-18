/**
 * Web Storage Adapter
 *
 * Storage adapter for web browsers using IndexedDB and Web Crypto API.
 *
 * Security Considerations:
 * - ⚠️ Browser storage is vulnerable to XSS attacks
 * - All sensitive data encrypted with AES-256-GCM
 * - Database encryption key stored in IndexedDB (no better option in browser)
 * - Use Content Security Policy (CSP) to mitigate XSS risks
 *
 * @example
 * ```typescript
 * const storage = new IndexedDbSignalProtocolStore();
 * await storage.initialize();
 *
 * // Store identity key
 * await storage.storeIdentityKey(keyPair);
 * ```
 */

import { openDB, IDBPDatabase, DBSchema } from 'idb';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';
import type {
  ISignalProtocolLocalStore,
  MessageRecord,
  SkippedSenderMessageKey,
  SessionTrustCommit,
} from '../../../types';
import { getErrorMessage } from '../../../utils/errors';
import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
} from '../../../keys';
import type { CompositeIdentityV1, ContactIdentityRecord, IdentityType } from '../../../keys/types';
import {
  acceptContactIdentityRotation as acceptRotation,
  createUnverifiedContactIdentityRecord,
  evaluateContactIdentityCandidate,
  validateContactIdentityRecord,
  verifyContactIdentityRecord,
} from '../../../keys/identity';
import type { SessionState, ProtocolAddress } from '../../../types';
import {
  IdentityKeyChange,
  StorageQuotaExceededError,
  TrustDirection,
} from '../../../types';
import {
  assertCurrentSessionRecord,
  type SessionRecord,
} from '../../../types/session';
import type { UserRecord, DeviceRecord, DeviceID } from '../../../types';
import type { Base64 } from '../../../types/utils';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import { deserializeSessionRecord, serializeSessionRecord } from '../session-codec';

/**
 * IndexedDB schema for Signal Protocol storage
 */
export {};
interface SignalProtocolDBSchema extends DBSchema {
  // Metadata store - contains database key and registration ID
  metadata: {
    key: string;
    value: Uint8Array | number | string;
  };

  // Identity keys store - our own identity
  identity: {
    key: string;
    value: Uint8Array;
  };

  // Contact identities store - TOFU tracking
  contacts: {
    key: string; // "userId"
    value: {
      key: string; // "userId" (keyPath)
      userId: string;
      data: Uint8Array; // Encrypted ContactIdentityRecord
      revision: number; // Non-authoritative CAS mirror, checked against encrypted record
    };
    indexes: {
      'by-user': string; // userId
    };
  };

  // PreKeys store
  prekeys: {
    key: string; // "signed" | "kyber" | "one-time-{id}"
    value: Uint8Array; // Encrypted
  };

  // Sessions store
  sessions: {
    key: string; // "userId.deviceId"
    value: {
      key: string; // "userId.deviceId" (keyPath)
      userId: string;
      deviceId: number;
      data: Uint8Array; // Encrypted SessionRecord
      updatedAt: number;
    };
    indexes: {
      'by-user': string; // userId
      'by-updated': number; // updatedAt
    };
  };

  // Security events log
  securityEvents: {
    key: number; // Auto-increment
    value: {
      type: string;
      userId: string;
      deviceId?: number;
      oldKey?: string;
      newKey?: string;
      detectedAt: number;
    };
    autoIncrement: true;
  };

  // SESAME users store - multi-device session management
  sesameUsers: {
    key: string; // userId
    value: {
      key: string; // userId (keyPath)
      data: Uint8Array; // Encrypted UserRecord (serialized)
      updatedAt: number;
    };
    indexes: {
      'by-updated': number; // updatedAt
    };
  };

  // Sender key records (current + previous states) for group messaging
  senderKeyRecords: {
    key: string;
    value: {
      key: string;
      groupId: string;
      userId: string;
      deviceId: number;
      /**
       * Every `senderKeyId` in this record, current and previous. They are
       * kept in plaintext so an incoming group message can be routed to a
       * group without decrypting every record on the device.
       *
       * These are the identifiers that already travel unencrypted on the
       * wire. Storing them in the clear on the local device discloses
       * nothing a relay could not already see. The key material stays inside
       * `data`.
       */
      senderKeyIds: string[];
      data: Uint8Array;
      updatedAt: number;
    };
    indexes: {
      'by-group': string;
      'by-sender-key-id': string;
    };
  };

  // Skipped sender keys for out-of-order sender-key messages
  skippedSenderKeys: {
    key: string;
    value: {
      key: string;
      senderKey: string;
      chainIndex: number;
      data: Uint8Array;
      createdAt: number;
    };
    indexes: {
      'by-sender': string;
      'by-created': number;
    };
  };

  // Message records for SESAME retry support
  messageRecords: {
    key: string;
    value: {
      key: string;
      sessionId: string;
      timestamp: number;
      createdAt: number;
      data: Uint8Array;
    };
    indexes: {
      'by-session': string;
      'by-created': number;
    };
  };
}

type SerializedDeviceRecord = Omit<DeviceRecord, 'identityKey'> & {
  identityKey: number[];
};

type SerializedUserRecord = Omit<UserRecord, 'devices'> & {
  devices: Array<[DeviceID, SerializedDeviceRecord]>;
};

/**
 * Compares stored ciphertext, not secret material - corrupt-row cleanup only
 * deletes a row whose bytes are still the ones that failed to deserialize.
 */
function encryptedBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * An IndexedDB add() that lost a create race fails with ConstraintError.
 * Checked by name rather than instanceof: the error crosses the idb
 * wrapper, and test doubles construct it without the DOMException class.
 */
function isConstraintError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'ConstraintError'
  );
}

/**
 * A write that exhausts the origin's storage quota fails with
 * QuotaExceededError. Checked by name rather than instanceof, like
 * isConstraintError. Engines differ on the constructor: a DOMException today,
 * an Error subclass in the newer storage spec. The name is the stable part.
 */
function isQuotaExceededError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'QuotaExceededError'
  );
}

function mapQuotaFailure(operation: string, error: unknown): unknown {
  if (!isQuotaExceededError(error)) return error;
  // The failure is Error-shaped by the name check above, but not always
  // instanceof Error: Node's DOMException does not extend Error.
  return new StorageQuotaExceededError(operation, error as Error);
}

/**
 * Rebinds every method of the store so a QuotaExceededError from
 * IndexedDB crosses the adapter boundary as the typed
 * StorageQuotaExceededError. Quota exhaustion can surface from any put,
 * add, or transaction commit. The mapping therefore lives at this one seam,
 * instead of inside each of the adapter's write paths. A method added later
 * is covered without a wrapper of its own. The failed transaction rolls back
 * whole, so the typed error always means the write did not persist.
 *
 * The walk starts at the instance's own prototype rather than this class's.
 * A subclass override is therefore the method that gets wrapped, instead of
 * being shadowed by a wrapper around the base method.
 */
function mapQuotaFailuresAtBoundary(store: IndexedDbSignalProtocolStore): void {
  const methods = new Map<string, (this: unknown, ...args: unknown[]) => unknown>();
  for (
    let prototype: object | null = Object.getPrototypeOf(store) as object | null;
    prototype !== null && prototype !== Object.prototype;
    prototype = Object.getPrototypeOf(prototype) as object | null
  ) {
    for (const name of Object.getOwnPropertyNames(prototype)) {
      // First found wins: the walk goes most-derived first.
      if (name === 'constructor' || methods.has(name)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
      if (typeof descriptor?.value !== 'function') continue;
      methods.set(name, descriptor.value as (this: unknown, ...args: unknown[]) => unknown);
    }
  }
  for (const [name, method] of methods) {
    (store as unknown as Record<string, unknown>)[name] = function mapped(
      this: unknown,
      ...args: unknown[]
    ): unknown {
      let result: unknown;
      try {
        result = method.apply(this, args);
      } catch (error) {
        throw mapQuotaFailure(name, error);
      }
      // Duck-typed rather than instanceof Promise so a cross-realm
      // promise or plain thenable from an override maps too.
      if (
        result !== null &&
        typeof result === 'object' &&
        typeof (result as { then?: unknown }).then === 'function'
      ) {
        return Promise.resolve(result).catch((error: unknown) => {
          throw mapQuotaFailure(name, error);
        });
      }
      return result;
    };
  }
}

/**
 * Web storage adapter using IndexedDB and Web Crypto API
 *
 * Implements ISignalProtocolLocalStore for web browsers with:
 * - IndexedDB for persistent storage
 * - Web Crypto API for AES-256-GCM encryption
 * - All sensitive data encrypted at rest
 * - TOFU (Trust On First Use) for contact verification
 */
export class IndexedDbSignalProtocolStore implements ISignalProtocolLocalStore {
  private db: IDBPDatabase<SignalProtocolDBSchema> | null = null;
  private databaseKey: Uint8Array | null = null;
  private readonly dbName = 'signal-protocol-storage';
  private readonly dbVersion = 6; // v6 indexes sender key records by senderKeyId
  private readonly _metadata = new Map<string, string>();

  constructor() {
    mapQuotaFailuresAtBoundary(this);
  }

  /**
   * Initialize the storage adapter
   *
   * - Opens IndexedDB database
   * - Creates object stores if needed
   * - Generates or retrieves database encryption key
   *
   * @throws Error if IndexedDB is not available
   */
  async initialize(): Promise<void> {
    // Check if IndexedDB is available
    if (typeof indexedDB === 'undefined') {
      throw new Error('IndexedDB is not available in this environment');
    }

    // Open database
    this.db = await openDB<SignalProtocolDBSchema>(this.dbName, this.dbVersion, {
      upgrade(db, oldVersion) {
        // Create metadata store
        if (!db.objectStoreNames.contains('metadata')) {
          db.createObjectStore('metadata');
        }

        // Create identity store
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity');
        }

        // Rows written before schema version 5 hold a single public key where
        // a composite trust record belongs. Dropping them is the only safe
        // reading: a single-key row cannot be reinterpreted as composite.
        if (oldVersion > 0 && oldVersion < 5 && db.objectStoreNames.contains('contacts')) {
          db.deleteObjectStore('contacts');
        }
        // Create contacts store with indexes
        if (!db.objectStoreNames.contains('contacts')) {
          const contactsStore = db.createObjectStore('contacts', { keyPath: 'key' });
          contactsStore.createIndex('by-user', 'userId');
        }

        // Create prekeys store
        if (!db.objectStoreNames.contains('prekeys')) {
          db.createObjectStore('prekeys');
        }

        // Create sessions store with indexes
        if (!db.objectStoreNames.contains('sessions')) {
          const sessionsStore = db.createObjectStore('sessions', { keyPath: 'key' });
          sessionsStore.createIndex('by-user', 'userId');
          sessionsStore.createIndex('by-updated', 'updatedAt');
        }

        // Create security events store
        if (!db.objectStoreNames.contains('securityEvents')) {
          db.createObjectStore('securityEvents', { autoIncrement: true });
        }

        // Create SESAME users store with index
        if (!db.objectStoreNames.contains('sesameUsers')) {
          const sesameStore = db.createObjectStore('sesameUsers', { keyPath: 'key' });
          sesameStore.createIndex('by-updated', 'updatedAt');
        }

        // A received group message names its sender key
        // by an opaque `senderKeyId` and nothing else, so records need an
        // index on that field. Rows written before v6 do not carry it and
        // cannot be indexed retroactively without decrypting each one. The
        // cost of dropping them is a round of sender key redistribution,
        // which the protocol already handles.
        if (oldVersion > 0 && oldVersion < 6 && db.objectStoreNames.contains('senderKeyRecords')) {
          db.deleteObjectStore('senderKeyRecords');
        }
        if (!db.objectStoreNames.contains('senderKeyRecords')) {
          const senderKeyStore = db.createObjectStore('senderKeyRecords', { keyPath: 'key' });
          senderKeyStore.createIndex('by-group', 'groupId');
          senderKeyStore.createIndex('by-sender-key-id', 'senderKeyIds', { multiEntry: true });
        }

        if (!db.objectStoreNames.contains('skippedSenderKeys')) {
          const skippedStore = db.createObjectStore('skippedSenderKeys', { keyPath: 'key' });
          skippedStore.createIndex('by-sender', 'senderKey');
          skippedStore.createIndex('by-created', 'createdAt');
        }

        if (!db.objectStoreNames.contains('messageRecords')) {
          const messageStore = db.createObjectStore('messageRecords', { keyPath: 'key' });
          messageStore.createIndex('by-session', 'sessionId');
          messageStore.createIndex('by-created', 'createdAt');
        }
      },
    });

    // Get or generate database encryption key
    const storedKey = await this.db.get('metadata', 'databaseKey');
    if (storedKey) {
      this.databaseKey = storedKey as Uint8Array;
    } else {
      // Generate new 32-byte key using Web Crypto. The add() call refuses to
      // overwrite, so when two connections bootstrap a fresh database
      // concurrently, exactly one key is ever stored. The loser adopts the
      // winner's key instead of encrypting records nobody else can read.
      const candidate = crypto.getRandomValues(new Uint8Array(32));
      try {
        await this.db.add('metadata', candidate, 'databaseKey');
        this.databaseKey = candidate;
      } catch (error) {
        if (!isConstraintError(error)) throw error;
        this.databaseKey = (await this.db.get(
          'metadata',
          'databaseKey'
        )) as Uint8Array;
      }

      // ⚠️ WARNING: Browser storage is vulnerable to XSS attacks
      console.warn(
        '[IndexedDbSignalProtocolStore] Database encryption key stored in IndexedDB. ' +
          'Ensure Content Security Policy (CSP) is configured to mitigate XSS risks.'
      );
    }
  }

  /**
   * Close the underlying IndexedDB connection and drop the in-memory copy of
   * the database key.
   *
   * An open connection blocks both deletion and version upgrades of the
   * database from any other connection. An application that signs out, clears
   * local state, or migrates must therefore be able to close the store. After
   * close(), call initialize() again before any other operation.
   */
  close(): void {
    this.db?.close();
    this.db = null;
    this.databaseKey = null;
  }

  /**
   * Get the database encryption key
   *
   * @returns 32-byte AES-256 key
   * @throws Error if not initialized
   */
  async getDatabaseKey(): Promise<Uint8Array> {
    if (!this.databaseKey) {
      throw new Error('IndexedDbSignalProtocolStore not initialized - call initialize() first');
    }
    return this.databaseKey;
  }

  // ============================================================================
  // Identity Key Management - Own Keys
  // ============================================================================

  async storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.encrypt(JSON.stringify(keyPair));
    await this.db!.put('identity', encrypted, `keyPair:${it}`);
  }

  async getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('identity', `keyPair:${it}`);
    if (!encrypted) return null;

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async hasIdentityKey(identityType?: IdentityType): Promise<boolean> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const key = await this.db!.get('identity', `keyPair:${it}`);
    return key !== undefined;
  }

  async getLocalRegistrationId(identityType?: IdentityType): Promise<number> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const id = await this.db!.get('metadata', `registrationId:${it}`);
    if (id === undefined) {
      return 0; // Default when not set
    }
    return id as number;
  }

  async setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    await this.db!.put('metadata', id, `registrationId:${it}`);
  }

  // ============================================================================
  // Identity Verification - Contact Keys (TOFU)
  // ============================================================================

  async saveContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<IdentityKeyChange> {
    this.ensureInitialized();
    const contactKey = this.serializeContactIdentityKey(address, identityType);
    for (;;) {
      const existing = await this.db!.get('contacts', contactKey);
      const record = existing ? await this.decodeContactRecord(existing.data) : null;
      if (existing && record && existing.revision !== record.revision) {
        throw new Error('Contact identity revision metadata does not match encrypted record');
      }
      const status = evaluateContactIdentityCandidate(record, identity, suppliedCommitment);
      if (status === 'NEW') {
        const created = createUnverifiedContactIdentityRecord(identity, Date.now());
        validateContactIdentityRecord(created);
        try {
          // The add() call refuses to overwrite. If a concurrent connection
          // pinned this contact first, re-evaluate the candidate against the
          // record that won, instead of silently replacing a TOFU pin.
          await this.db!.add('contacts', {
            key: contactKey,
            userId: address.userId,
            data: await this.encrypt(JSON.stringify(created)),
            revision: created.revision,
          });
        } catch (error) {
          if (isConstraintError(error)) continue;
          throw error;
        }
        return IdentityKeyChange.NEW_IDENTITY;
      }
      if (status === 'MATCH') return IdentityKeyChange.UNCHANGED;
      if (status === 'ROLLBACK') return IdentityKeyChange.ROLLBACK;
      return IdentityKeyChange.CHANGED;
    }
  }

  async getContactIdentity(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): Promise<ContactIdentityRecord | null> {
    this.ensureInitialized();
    const contactKey = this.serializeContactIdentityKey(address, identityType);
    const contact = await this.db!.get('contacts', contactKey);
    if (!contact) return null;
    const record = await this.decodeContactRecord(contact.data);
    if (record.revision !== contact.revision) {
      throw new Error('Contact identity revision metadata does not match encrypted record');
    }
    return record;
  }

  async acceptContactIdentityRotation(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return await this.acceptContactIdentityRotationAndDeleteSessions(
      address,
      identity,
      identityType,
      suppliedCommitment
    );
  }

  async acceptContactIdentityRotationAndDeleteSessions(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    this.ensureInitialized();
    const key = this.serializeContactIdentityKey(address, identityType);
    const existing = await this.getContactIdentity(address, identityType);
    if (!existing) throw new Error('Cannot rotate an unseen identity');
    const replacement = acceptRotation(existing, identity, Date.now(), suppliedCommitment);
    validateContactIdentityRecord(replacement);
    const encrypted = await this.encrypt(JSON.stringify(replacement));

    const tx = this.db!.transaction(['contacts', 'sessions'], 'readwrite');
    const contacts = tx.objectStore('contacts');
    const current = await contacts.get(key);
    if (!current || current.revision !== existing.revision) {
      await tx.done;
      throw new Error('Contact identity changed concurrently during rotation');
    }
    // Read the doomed session keys before mutating, then enter every
    // mutation in one synchronous batch. A dying page closes its connection
    // gracefully, and a transaction that is idle at an await boundary then
    // commits the writes it already holds. A cursor walk that deletes as
    // it goes leaves windows where the new pin commits with sessions still
    // trusted under the old identity.
    const sessions = tx.objectStore('sessions');
    const doomedKeys = await sessions.index('by-user').getAllKeys(address.userId);
    await Promise.all([
      contacts.put({
        key,
        userId: address.userId,
        data: encrypted,
        revision: replacement.revision,
      }),
      ...doomedKeys.map((sessionKey) => sessions.delete(sessionKey)),
      tx.done,
    ]);
    return replacement;
  }

  async verifyContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    this.ensureInitialized();
    const key = this.serializeContactIdentityKey(address, identityType);
    const existingRow = await this.db!.get('contacts', key);
    const existing = existingRow ? await this.decodeContactRecord(existingRow.data) : null;
    if (!existing) throw new Error('Cannot verify an unseen identity');
    const verified = verifyContactIdentityRecord(existing, identity, Date.now(), suppliedCommitment);
    const encrypted = await this.encrypt(JSON.stringify(verified));
    const tx = this.db!.transaction('contacts', 'readwrite');
    const contacts = tx.objectStore('contacts');
    const current = await contacts.get(key);
    if (!current || current.revision !== existing.revision) {
      await tx.done;
      throw new Error('Contact identity changed concurrently during verification');
    }
    await contacts.put({
      key,
      userId: address.userId,
      data: encrypted,
      revision: verified.revision,
    });
    await tx.done;
    return verified;
  }

  async isTrustedIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    _direction: TrustDirection,
    identityType?: IdentityType
  ): Promise<boolean> {
    this.ensureInitialized();
    const status = evaluateContactIdentityCandidate(
      await this.getContactIdentity(address, identityType),
      identity
    );
    return status === 'NEW' || status === 'MATCH';
  }

  // ============================================================================
  // PreKey Management
  // ============================================================================

  async storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.encrypt(JSON.stringify(signedPreKey));
    // Store by identityType:keyId to support multiple prekeys (grace period)
    await this.db!.put('prekeys', encrypted, `signed:${it}:${signedPreKey.keyId}`);
    await this.cleanupExpiredEcSignedPreKeys(identityType);
  }

  async getEcSignedPreKey(
    keyId?: number,
    identityType?: IdentityType
  ): Promise<EcSignedPreKey | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';

    if (keyId !== undefined) {
      // Look up by specific keyId
      const encrypted = await this.db!.get('prekeys', `signed:${it}:${keyId}`);
      if (!encrypted) return null;
      const decrypted = await this.decrypt(encrypted);
      return JSON.parse(decrypted);
    }

    // Return the most recent EC signed prekey
    const allPrekeys = await this.getAllEcSignedPreKeys(identityType);
    if (allPrekeys.length === 0) return null;
    return allPrekeys.reduce((latest, current) =>
      current.keyId > latest.keyId ? current : latest
    );
  }

  async getAllEcSignedPreKeys(identityType?: IdentityType): Promise<EcSignedPreKey[]> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const prefix = `signed:${it}:`;
    const allKeys = await this.db!.getAllKeys('prekeys');
    const signedKeys = allKeys.filter((key) => typeof key === 'string' && key.startsWith(prefix));

    const prekeys: EcSignedPreKey[] = [];
    for (const key of signedKeys) {
      const encrypted = await this.db!.get('prekeys', key);
      if (encrypted) {
        const decrypted = await this.decrypt(encrypted);
        prekeys.push(JSON.parse(decrypted));
      }
    }
    return prekeys;
  }

  async removeEcSignedPreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    await this.db!.delete('prekeys', `signed:${it}:${keyId}`);
  }

  private async cleanupExpiredEcSignedPreKeys(identityType?: IdentityType): Promise<void> {
    const allPrekeys = await this.getAllEcSignedPreKeys(identityType);
    if (allPrekeys.length <= 1) return;

    const cutoff = Date.now() - MAX_UNACKNOWLEDGED_SESSION_AGE_MS;
    const newest = allPrekeys.reduce((a, b) => (a.keyId > b.keyId ? a : b));

    for (const prekey of allPrekeys) {
      if (prekey.keyId !== newest.keyId && prekey.timestamp && prekey.timestamp < cutoff) {
        await this.removeEcSignedPreKey(prekey.keyId, identityType);
      }
    }
  }

  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';

    // Store each EC one-time prekey
    for (const prekey of prekeys) {
      const encrypted = await this.encrypt(JSON.stringify(prekey));
      await this.db!.put('prekeys', encrypted, `one-time:${it}:${prekey.keyId}`);
    }
  }

  async getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const prefix = `one-time:${it}:`;

    // First, collect all encrypted values (within transaction)
    const encryptedPreKeys: Array<{ id: number; encrypted: Uint8Array }> = [];
    const tx = this.db!.transaction('prekeys', 'readonly');
    const store = tx.objectStore('prekeys');

    // Get all keys - do not decrypt inside the iteration to avoid transaction timeout
    for await (const cursor of store.iterate()) {
      const key = cursor.key as string;
      if (key.startsWith(prefix)) {
        const id = parseInt(key.slice(prefix.length), 10);
        encryptedPreKeys.push({ id, encrypted: cursor.value });
      }
    }

    // Wait for transaction to complete
    await tx.done;

    // Then decrypt all values (outside transaction)
    const prekeys: EcOneTimePreKey[] = [];
    for (const { encrypted } of encryptedPreKeys) {
      const decrypted = await this.decrypt(encrypted);
      prekeys.push(JSON.parse(decrypted));
    }

    return prekeys;
  }

  async removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    await this.db!.delete('prekeys', `one-time:${it}:${preKeyId}`);
  }

  async storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.encrypt(JSON.stringify(kyberPreKey));
    await this.db!.put('prekeys', encrypted, `kyber:${it}`);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('prekeys', `kyber:${it}`);
    if (!encrypted) return null;

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';

    // Store usage metadata
    const metadata = {
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes: Array.from(baseKeyBytes),
      usedAt: Date.now(),
    };

    const encrypted = await this.encrypt(JSON.stringify(metadata));
    await this.db!.put('metadata', encrypted, `kyber-used:${it}:${kyberPreKeyId}`);
  }

  // ============================================================================
  // KEM One-Time PreKey Management (Per-Session Post-Quantum Forward Secrecy)
  // ============================================================================
  // NOTE: This adapter is for web browsers (IndexedDB).
  // Expo apps should still prefer ExpoSignalProtocolStore for the native SQLite backend.

  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';

    for (const prekey of prekeys) {
      const encrypted = await this.encrypt(JSON.stringify(prekey));
      await this.db!.put('prekeys', encrypted, `kem-one-time:${it}:${prekey.keyId}`);
    }
  }

  async getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const prefix = `kem-one-time:${it}:`;
    const allKeys = await this.db!.getAllKeys('prekeys');
    const kemKeys = allKeys.filter((key) => typeof key === 'string' && key.startsWith(prefix));

    const prekeys: KemOneTimePreKey[] = [];
    for (const key of kemKeys) {
      const encrypted = await this.db!.get('prekeys', key);
      if (encrypted) {
        const decrypted = await this.decrypt(encrypted);
        prekeys.push(JSON.parse(decrypted));
      }
    }

    return prekeys;
  }

  async getKemOneTimePreKey(
    keyId: number,
    identityType?: IdentityType
  ): Promise<KemOneTimePreKey | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('prekeys', `kem-one-time:${it}:${keyId}`);
    if (!encrypted) return null;

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    await this.db!.delete('prekeys', `kem-one-time:${it}:${keyId}`);
  }

  async getKemOneTimePreKeyCount(identityType?: IdentityType): Promise<number> {
    const prekeys = await this.getKemOneTimePreKeys(identityType);
    return prekeys.length;
  }

  // ============================================================================
  // Session Management - Modern API
  // ============================================================================

  async storeSessionRecord(address: ProtocolAddress, record: SessionRecord): Promise<void> {
    this.ensureInitialized();
    assertCurrentSessionRecord(record);
    const addressKey = this.serializeAddress(address);
    const encrypted = await this.encrypt(serializeSessionRecord(record));

    await this.db!.put('sessions', {
      key: addressKey,
      userId: address.userId,
      deviceId: address.deviceId,
      data: encrypted,
      updatedAt: Date.now(),
    });
  }

  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    this.ensureInitialized();
    const addressKey = this.serializeAddress(address);
    const stored = await this.db!.get('sessions', addressKey);

    if (!stored) return null;

    const decrypted = await this.decrypt(stored.data);
    try {
      return deserializeSessionRecord(decrypted);
    } catch {
      await this.db!.delete('sessions', addressKey);
      return null;
    }
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    this.ensureInitialized();
    assertCurrentSessionRecord(commit.record);
    const addressKey = this.serializeAddress(commit.address);
    const contactKey = this.serializeContactIdentityKey(
      commit.address,
      commit.contactIdentityType
    );
    const existingContactRow = await this.db!.get('contacts', contactKey);
    const existingContact = existingContactRow
      ? await this.decodeContactRecord(existingContactRow.data)
      : null;
    if (
      existingContactRow &&
      existingContact &&
      existingContactRow.revision !== existingContact.revision
    ) {
      throw new Error('Contact identity revision metadata does not match encrypted record');
    }
    const contactStatus = evaluateContactIdentityCandidate(
      existingContact,
      commit.contactIdentity
    );
    if (contactStatus !== 'NEW' && contactStatus !== 'MATCH') {
      throw new Error(`Atomic session/trust commit rejected contact identity status ${contactStatus}`);
    }
    const newContact =
      contactStatus === 'NEW'
        ? createUnverifiedContactIdentityRecord(commit.contactIdentity, Date.now())
        : null;
    const encryptedContact = newContact
      ? await this.encrypt(JSON.stringify(newContact))
      : undefined;
    const encrypted = await this.encrypt(serializeSessionRecord(commit.record));
    const tx = this.db!.transaction(['contacts', 'prekeys', 'sessions'], 'readwrite');
    const contacts = tx.objectStore('contacts');
    const prekeys = tx.objectStore('prekeys');
    const currentContactRow = await contacts.get(contactKey);
    if (
      existingContactRow
        ? !currentContactRow || currentContactRow.revision !== existingContactRow.revision
        : !!currentContactRow
    ) {
      await tx.done;
      throw new Error('Contact identity changed during atomic session/trust commit');
    }
    const ecPreKeyStorageKey =
      commit.oneTimePreKeyId === undefined
        ? undefined
        : `one-time:${commit.localIdentityType}:${commit.oneTimePreKeyId}`;
    const kemPreKeyStorageKey =
      commit.kemOneTimePreKeyId === undefined
        ? undefined
        : `kem-one-time:${commit.localIdentityType}:${commit.kemOneTimePreKeyId}`;
    if (ecPreKeyStorageKey && !(await prekeys.get(ecPreKeyStorageKey))) {
      await tx.done;
      throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
    }
    if (kemPreKeyStorageKey && !(await prekeys.get(kemPreKeyStorageKey))) {
      await tx.done;
      throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
    }
    // Every mutation must enter the transaction in one synchronous batch.
    // A dying page closes its connection gracefully, and a transaction that
    // is idle at an await boundary then commits the writes it already holds.
    // An await between mutations is a window for a partial commit.
    const writes: Promise<unknown>[] = [];
    if (newContact && encryptedContact) {
      writes.push(
        contacts.put({
          key: contactKey,
          userId: commit.address.userId,
          data: encryptedContact,
          revision: newContact.revision,
        })
      );
    }
    writes.push(
      tx.objectStore('sessions').put({
        key: addressKey,
        userId: commit.address.userId,
        deviceId: commit.address.deviceId,
        data: encrypted,
        updatedAt: Date.now(),
      })
    );
    if (ecPreKeyStorageKey) writes.push(prekeys.delete(ecPreKeyStorageKey));
    if (kemPreKeyStorageKey) writes.push(prekeys.delete(kemPreKeyStorageKey));
    await Promise.all([...writes, tx.done]);
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    this.ensureInitialized();
    const addressKey = this.serializeAddress(address);
    await this.db!.delete('sessions', addressKey);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    this.ensureInitialized();

    // With SessionRecord, archiving is handled via SessionRecord.archiveCurrent()
    // This method updates or replaces the session state
    if (newSession) {
      const record = await this.getSessionRecord(address);

      if (record) {
        // Update existing session with new state
        record.currentSession = newSession;
        if (record.metadata) {
          record.metadata.lastSentAt = Date.now();
        }
        await this.storeSessionRecord(address, record);
      }
    } else {
      // If no new session, just delete the old one
      await this.deleteSessionRecord(address);
    }
  }

  async getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    this.ensureInitialized();

    // Collect encrypted rows first - decrypting inside the iteration would
    // deactivate the transaction and the next cursor advance throws
    // TransactionInactiveError on spec-conformant engines (Firefox, WebKit)
    const rows: Array<{ key: string; data: Uint8Array }> = [];
    const tx = this.db!.transaction('sessions', 'readonly');
    const index = tx.objectStore('sessions').index('by-user');

    for await (const cursor of index.iterate(userId)) {
      rows.push({ key: cursor.primaryKey as string, data: cursor.value.data });
    }
    await tx.done;

    const records: SessionRecord[] = [];
    const corruptRows: Array<{ key: string; data: Uint8Array }> = [];
    for (const row of rows) {
      const decrypted = await this.decrypt(row.data);
      try {
        records.push(deserializeSessionRecord(decrypted));
      } catch {
        corruptRows.push(row);
      }
    }

    if (corruptRows.length > 0) {
      // Re-read and compare inside one readwrite transaction. A concurrent
      // writer may have replaced the corrupt bytes with a valid record since
      // the snapshot above, and an unconditional delete would destroy it.
      // Every await here is an IDB request, so the transaction stays active.
      const cleanupTx = this.db!.transaction('sessions', 'readwrite');
      const store = cleanupTx.objectStore('sessions');
      for (const row of corruptRows) {
        const current = await store.get(row.key);
        if (current && encryptedBytesEqual(current.data, row.data)) {
          await store.delete(row.key);
        }
      }
      await cleanupTx.done;
    }

    return records;
  }

  async hasSession(address: ProtocolAddress): Promise<boolean> {
    this.ensureInitialized();
    return (await this.getSessionRecord(address)) !== null;
  }

  // ============================================================================
  // Utility
  // ============================================================================

  async getSessionCount(): Promise<number> {
    this.ensureInitialized();
    return await this.db!.count('sessions');
  }

  async clearAllKeys(): Promise<void> {
    this.ensureInitialized();

    // Clear all object stores
    await this.db!.clear('metadata');
    await this.db!.clear('identity');
    await this.db!.clear('contacts');
    await this.db!.clear('prekeys');
    await this.db!.clear('sessions');
    await this.db!.clear('securityEvents');
    await this.db!.clear('sesameUsers');
    await this.db!.clear('senderKeyRecords');
    await this.db!.clear('skippedSenderKeys');
    await this.db!.clear('messageRecords');
    this._metadata.clear();

    // Generate new database encryption key after clearing
    this.databaseKey = crypto.getRandomValues(new Uint8Array(32));
    await this.db!.put('metadata', this.databaseKey, 'databaseKey');
  }

  // ============================================================================
  // Metadata storage
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    if (this._metadata.has(key)) {
      return this._metadata.get(key) ?? null;
    }

    this.ensureInitialized();
    const stored = await this.db!.get('metadata', `meta:${key}`);
    if (typeof stored !== 'string') {
      return null;
    }

    this._metadata.set(key, stored);
    return stored;
  }

  async setMetadata(key: string, value: string): Promise<void> {
    this.ensureInitialized();
    this._metadata.set(key, value);
    await this.db!.put('metadata', value, `meta:${key}`);
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Throw when the adapter is not initialized
   * @throws Error if not initialized
   */
  private ensureInitialized(): void {
    if (!this.db || !this.databaseKey) {
      throw new Error('IndexedDbSignalProtocolStore not initialized - call initialize() first');
    }
  }

  /**
   * Serialize ProtocolAddress to string key
   */
  private serializeAddress(address: ProtocolAddress): string {
    return `${address.userId}.${address.deviceId}`;
  }

  private serializeContactIdentityKey(address: ProtocolAddress, identityType?: IdentityType): string {
    return `${address.userId}:${identityType ?? 'aci'}`;
  }

  private async decodeContactRecord(data: Uint8Array): Promise<ContactIdentityRecord> {
    const record = JSON.parse(await this.decrypt(data)) as ContactIdentityRecord;
    validateContactIdentityRecord(record);
    return record;
  }

  /**
   * Encrypt data using AES-256-GCM with Web Crypto API
   *
   * @param plaintext - Data to encrypt
   * @returns IV (12 bytes) + ciphertext + auth tag (16 bytes)
   */
  private async encrypt(plaintext: string): Promise<Uint8Array> {
    if (!this.databaseKey) {
      throw new Error('Database key not available');
    }

    // Import key for AES-GCM
    const key = await crypto.subtle.importKey(
      'raw',
      this.databaseKey as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    // Generate random IV (12 bytes for GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encode plaintext
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Encrypt
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

    // Combine IV + ciphertext (auth tag is included in ciphertext by Web Crypto)
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), 12);

    return result;
  }

  /**
   * Decrypt data using AES-256-GCM with Web Crypto API
   *
   * @param encrypted - IV (12 bytes) + ciphertext + auth tag (16 bytes)
   * @returns Decrypted plaintext
   */
  private async decrypt(encrypted: Uint8Array): Promise<string> {
    if (!this.databaseKey) {
      throw new Error('Database key not available');
    }

    // Extract IV and ciphertext
    const iv = encrypted.slice(0, 12);
    const ciphertext = encrypted.slice(12);

    // Import key for AES-GCM
    const key = await crypto.subtle.importKey(
      'raw',
      this.databaseKey as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Decrypt
    try {
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

      // Decode plaintext
      const decoder = new TextDecoder();
      return decoder.decode(plaintext);
    } catch (error) {
      throw new Error(`Decryption failed: ${getErrorMessage(error)}`);
    }
  }

  // ============================================================================
  // SESAME Serialization Helpers
  // ============================================================================

  /**
   * Serialize UserRecord for JSON storage
   * Converts Map<DeviceID, DeviceRecord> to array of [deviceId, deviceRecord] pairs
   */
  private serializeUserRecord(record: UserRecord): SerializedUserRecord {
    return {
      ...record,
      devices: Array.from(record.devices.entries(), ([deviceId, device]) => [
        deviceId,
        {
          ...device,
          identityKey: Array.from(device.identityKey),
        },
      ]),
    };
  }

  /**
   * Deserialize UserRecord from JSON storage
   * Converts array of [deviceId, deviceRecord] pairs back to Map
   */
  private deserializeUserRecord(data: SerializedUserRecord): UserRecord {
    return {
      ...data,
      devices: new Map(
        data.devices.map(([deviceId, device]) => [
          deviceId,
          {
            ...device,
            identityKey: new Uint8Array(device.identityKey),
          },
        ])
      ),
    };
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    this.ensureInitialized();

    const entry = await this.db!.get('sesameUsers', userId);
    if (!entry) {
      return null;
    }

    const json = await this.decrypt(entry.data);
    return this.deserializeUserRecord(JSON.parse(json));
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    this.ensureInitialized();

    const serialized = this.serializeUserRecord(record);
    const encrypted = await this.encrypt(JSON.stringify(serialized));

    await this.db!.put('sesameUsers', {
      key: userId,
      data: encrypted,
      updatedAt: Date.now(),
    });
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    const userRecord = await this.getUserRecord(userId);
    if (!userRecord) {
      return null;
    }

    return userRecord.devices.get(deviceId) || null;
  }

  async setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void> {
    // Get or create UserRecord
    let userRecord = await this.getUserRecord(userId);
    if (!userRecord) {
      // Auto-create UserRecord when adding first device
      userRecord = {
        userId: userId,
        devices: new Map(),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    }

    // Update device
    userRecord.devices.set(deviceId, record);
    userRecord.updatedAt = Date.now();

    await this.setUserRecord(userId, userRecord);
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    const userRecord = await this.getUserRecord(userId);
    if (!userRecord) {
      return;
    }

    userRecord.devices.delete(deviceId);
    userRecord.updatedAt = Date.now();

    // Auto-cleanup: remove UserRecord if no devices remain
    if (userRecord.devices.size === 0) {
      await this.db!.delete('sesameUsers', userId);
    } else {
      await this.setUserRecord(userId, userRecord);
    }
  }

  async deleteStaleRecords(maxLatency: number): Promise<number> {
    this.ensureInitialized();

    const now = Date.now();
    let deletedCount = 0;

    // Get all user IDs
    const userIds = await this.getAllUserIds();

    for (const userId of userIds) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      // Check each device
      const devicesToDelete: number[] = [];

      for (const [deviceId, deviceRecord] of userRecord.devices) {
        // Delete devices that:
        // 1. Have no session OR (no current session AND no archived sessions)
        // 2. AND have not been updated within maxLatency
        const hasNoSessions =
          !deviceRecord.session ||
          (!deviceRecord.session.currentSession &&
            Object.keys(deviceRecord.session.archivedSessions).length === 0);
        const isStale = now - deviceRecord.updatedAt > maxLatency;

        if (hasNoSessions && isStale) {
          devicesToDelete.push(deviceId);
        }
      }

      // Delete stale devices
      for (const deviceId of devicesToDelete) {
        await this.deleteDeviceRecord(userId, deviceId);
        deletedCount++;
      }
    }

    return deletedCount;
  }

  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    this.ensureInitialized();

    const now = Date.now();
    let deletedCount = 0;

    // Get all user IDs
    const userIds = await this.getAllUserIds();

    for (const userId of userIds) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      // Check each device
      for (const [deviceId, deviceRecord] of userRecord.devices) {
        if (!deviceRecord.session) continue;

        let modified = false;

        // Check current session - use metadata.createdAt if available, otherwise session.createdAt
        if (deviceRecord.session.currentSession) {
          const createdAt =
            deviceRecord.session.metadata?.createdAt ??
            deviceRecord.session.currentSession.createdAt;
          if (now - createdAt > maxRecv) {
            deviceRecord.session.currentSession = null;
            modified = true;
            deletedCount++;
          }
        }

        // Filter archived sessions based on createdAt
        const originalCount = Object.keys(deviceRecord.session.archivedSessions).length;
        const archivedKeys = Object.keys(deviceRecord.session.archivedSessions) as Base64[];
        for (const baseKey of archivedKeys) {
          const session = deviceRecord.session.archivedSessions[baseKey];
          if (session && now - session.createdAt > maxRecv) {
            delete deviceRecord.session.archivedSessions[baseKey];
          }
        }
        const removed = originalCount - Object.keys(deviceRecord.session.archivedSessions).length;
        deletedCount += removed;

        if (removed > 0) {
          modified = true;
        }

        // Save if modified
        if (modified) {
          deviceRecord.updatedAt = Date.now();
          await this.setDeviceRecord(userId, deviceId, deviceRecord);
        }
      }
    }

    return deletedCount;
  }

  async getAllUserIds(): Promise<string[]> {
    this.ensureInitialized();

    const userIds: string[] = [];
    const tx = this.db!.transaction('sesameUsers', 'readonly');

    for await (const cursor of tx.store) {
      userIds.push(cursor.key);
    }

    return userIds;
  }

  async getSesameDeviceIds(userId: string): Promise<number[]> {
    const userRecord = await this.getUserRecord(userId);
    if (!userRecord) {
      return [];
    }

    return Array.from(userRecord.devices.keys());
  }

  async getDeviceSession(userId: string, deviceId: number): Promise<SessionRecord | null> {
    const deviceRecord = await this.getDeviceRecord(userId, deviceId);
    return deviceRecord?.session ?? null;
  }

  async setDeviceSession(userId: string, deviceId: number, session: SessionRecord): Promise<void> {
    const deviceRecord = await this.getDeviceRecord(userId, deviceId);
    if (deviceRecord) {
      deviceRecord.session = session;
      await this.setDeviceRecord(userId, deviceId, deviceRecord);
    }
  }

  // ============================================================================
  // Sender Keys Management (Group Messaging)
  // ============================================================================

  async storeSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    state: SenderKeyState
  ): Promise<void> {
    await this.storeSenderKeyRecord(groupId, userId, deviceId, [state]);
  }

  async getSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null> {
    const record = await this.getSenderKeyRecord(groupId, userId, deviceId);
    return record?.[0] ?? null;
  }

  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    this.ensureInitialized();
    await this.db!.delete(
      'senderKeyRecords',
      this.getSenderKeyRecordStorageKey(groupId, userId, deviceId)
    );
  }

  async resolveGroupForSenderKeyId(
    senderKeyId: string,
    userId: string,
    deviceId: number
  ): Promise<string | null> {
    this.ensureInitialized();
    if (!senderKeyId) return null;

    const tx = this.db!.transaction('senderKeyRecords', 'readonly');
    const index = tx.objectStore('senderKeyRecords').index('by-sender-key-id');

    // An id is unique to one sender key, but the index is not scoped by
    // sender. The sender still has to match, because another device claiming
    // a known id must not resolve to that device's group.
    for await (const cursor of index.iterate(senderKeyId)) {
      const row = cursor.value;
      if (row.userId === userId && row.deviceId === deviceId) {
        return row.groupId;
      }
    }

    return null;
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    this.ensureInitialized();

    // Collect encrypted rows first - decrypting inside the iteration would
    // deactivate the transaction and the next cursor advance throws
    // TransactionInactiveError on spec-conformant engines (Firefox, WebKit)
    const encryptedRows: Uint8Array[] = [];
    const tx = this.db!.transaction('senderKeyRecords', 'readonly');
    const index = tx.objectStore('senderKeyRecords').index('by-group');

    for await (const cursor of index.iterate(groupId)) {
      encryptedRows.push(cursor.value.data);
    }
    await tx.done;

    const states: SenderKeyState[] = [];
    for (const data of encryptedRows) {
      const decrypted = await this.decrypt(data);
      const record = JSON.parse(decrypted) as SenderKeyState[];
      if (record[0]) {
        states.push(record[0]);
      }
    }

    return states;
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    this.ensureInitialized();

    const keys: string[] = [];
    const tx = this.db!.transaction('senderKeyRecords', 'readonly');
    const index = tx.objectStore('senderKeyRecords').index('by-group');

    for await (const cursor of index.iterate(groupId)) {
      keys.push(cursor.primaryKey as string);
    }

    await Promise.all(keys.map((key) => this.db!.delete('senderKeyRecords', key)));
    return keys.length;
  }

  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void> {
    this.ensureInitialized();
    if (states.length === 0) {
      return;
    }

    const encrypted = await this.encrypt(JSON.stringify(states));
    await this.db!.put('senderKeyRecords', {
      key: this.getSenderKeyRecordStorageKey(groupId, userId, deviceId),
      groupId,
      userId,
      deviceId,
      // Indexed so `resolveGroupForSenderKeyId` is a lookup rather than a
      // decrypt-everything scan. Previous states are included: a message
      // encrypted just before a rotation is still in flight when the rotation
      // lands and names the superseded key.
      senderKeyIds: states.map((state) => state.senderKeyId).filter(Boolean),
      data: encrypted,
      updatedAt: Date.now(),
    });
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    this.ensureInitialized();
    const stored = await this.db!.get(
      'senderKeyRecords',
      this.getSenderKeyRecordStorageKey(groupId, userId, deviceId)
    );
    if (!stored) {
      return null;
    }

    const decrypted = await this.decrypt(stored.data);
    return JSON.parse(decrypted);
  }

  // ============================================================================
  // Skipped Sender Keys
  // ============================================================================

  async storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(messageKey));
    await this.db!.put('skippedSenderKeys', {
      key: this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex),
      senderKey: this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId),
      chainIndex,
      data: encrypted,
      createdAt: Date.now(),
    });
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null> {
    this.ensureInitialized();
    const stored = await this.db!.get(
      'skippedSenderKeys',
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex)
    );
    if (!stored) {
      return null;
    }

    const decrypted = await this.decrypt(stored.data);
    return JSON.parse(decrypted);
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    this.ensureInitialized();
    await this.db!.delete(
      'skippedSenderKeys',
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex)
    );
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    this.ensureInitialized();
    let count = 0;
    const tx = this.db!.transaction('skippedSenderKeys', 'readonly');
    const index = tx.objectStore('skippedSenderKeys').index('by-sender');

    for await (const cursor of index.iterate(
      this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId)
    )) {
      void cursor;
      count++;
    }

    return count;
  }

  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    this.ensureInitialized();
    const matches: Array<{ key: string; chainIndex: number }> = [];
    const tx = this.db!.transaction('skippedSenderKeys', 'readonly');
    const index = tx.objectStore('skippedSenderKeys').index('by-sender');

    for await (const cursor of index.iterate(
      this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId)
    )) {
      matches.push({ key: cursor.primaryKey as string, chainIndex: cursor.value.chainIndex });
    }

    matches.sort((a, b) => a.chainIndex - b.chainIndex);
    const toDelete = matches.slice(0, count);
    await Promise.all(toDelete.map(({ key }) => this.db!.delete('skippedSenderKeys', key)));
    return toDelete.length;
  }

  // ============================================================================
  // Message Record Storage (Not Yet Implemented)
  // Retry records are indexed by the client timestamp assigned before encryption.
  // ============================================================================

  async storeMessageRecord(record: MessageRecord): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(record));
    await this.db!.put('messageRecords', {
      key: this.getMessageRecordStorageKey(record.sessionId, record.timestamp),
      sessionId: record.sessionId,
      timestamp: record.timestamp,
      createdAt: record.createdAt,
      data: encrypted,
    });
  }

  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    this.ensureInitialized();
    const stored = await this.db!.get(
      'messageRecords',
      this.getMessageRecordStorageKey(sessionId, timestamp)
    );
    if (!stored) {
      return null;
    }

    const decrypted = await this.decrypt(stored.data);
    return JSON.parse(decrypted);
  }

  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    this.ensureInitialized();
    await this.db!.delete('messageRecords', this.getMessageRecordStorageKey(sessionId, timestamp));
  }

  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    this.ensureInitialized();
    const cutoff = Date.now() - maxAgeMs;
    const matches: string[] = [];
    const tx = this.db!.transaction('messageRecords', 'readonly');
    const index = tx.objectStore('messageRecords').index('by-created');

    for await (const cursor of index.iterate()) {
      if (cursor.value.createdAt < cutoff) {
        matches.push(cursor.primaryKey as string);
      }
    }

    await Promise.all(matches.map((key) => this.db!.delete('messageRecords', key)));
    return matches.length;
  }

  async clearAllMessageRecords(): Promise<number> {
    this.ensureInitialized();
    const count = await this.db!.count('messageRecords');
    await this.db!.clear('messageRecords');
    return count;
  }

  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    this.ensureInitialized();
    const matches: string[] = [];
    const tx = this.db!.transaction('messageRecords', 'readonly');
    const index = tx.objectStore('messageRecords').index('by-session');

    for await (const cursor of index.iterate(sessionId)) {
      matches.push(cursor.primaryKey as string);
    }

    await Promise.all(matches.map((key) => this.db!.delete('messageRecords', key)));
    return matches.length;
  }

  // ============================================================================
  // Key Recovery Methods (Bug #7 - Identifier Collision Recovery)
  // ============================================================================

  async getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    const prekeys = await this.getAllEcSignedPreKeys(identityType);
    return prekeys.reduce((max, prekey) => Math.max(max, prekey.keyId), 0);
  }

  async getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    const prekey = await this.getKyberPreKey(identityType);
    return prekey?.keyId ?? 0;
  }

  async deleteAllPreKeys(identityType?: IdentityType): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const allKeys = await this.db!.getAllKeys('prekeys');
    let ecSignedPreKeys = 0;
    let ecOneTimePreKeys = 0;
    let kyberPreKeys = 0;
    let kemOneTimePreKeys = 0;

    for (const rawKey of allKeys) {
      if (typeof rawKey !== 'string') {
        continue;
      }

      if (rawKey.startsWith(`signed:${it}:`)) {
        await this.db!.delete('prekeys', rawKey);
        ecSignedPreKeys++;
      } else if (rawKey.startsWith(`one-time:${it}:`)) {
        await this.db!.delete('prekeys', rawKey);
        ecOneTimePreKeys++;
      } else if (rawKey === `kyber:${it}`) {
        await this.db!.delete('prekeys', rawKey);
        kyberPreKeys++;
      } else if (rawKey.startsWith(`kem-one-time:${it}:`)) {
        await this.db!.delete('prekeys', rawKey);
        kemOneTimePreKeys++;
      }
    }

    const metadataKeys = await this.db!.getAllKeys('metadata');
    for (const rawKey of metadataKeys) {
      if (typeof rawKey === 'string' && rawKey.startsWith(`kyber-used:${it}:`)) {
        await this.db!.delete('metadata', rawKey);
      }
    }

    return { ecSignedPreKeys, ecOneTimePreKeys, kyberPreKeys, kemOneTimePreKeys };
  }

  async clearAllSessions(): Promise<void> {
    this.ensureInitialized();
    await this.db!.clear('sessions');
    await this.db!.clear('sesameUsers');
  }

  async getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    this.ensureInitialized();
    const allPrekeys = await this.db!.getAllKeys('prekeys');
    let ecSignedPreKeys = 0;
    let ecOneTimePreKeys = 0;
    let kyberPreKeys = 0;
    let kemOneTimePreKeys = 0;

    for (const rawKey of allPrekeys) {
      if (typeof rawKey !== 'string') {
        continue;
      }

      if (rawKey.startsWith('signed:')) {
        ecSignedPreKeys++;
      } else if (rawKey.startsWith('one-time:')) {
        ecOneTimePreKeys++;
      } else if (rawKey.startsWith('kyber:')) {
        kyberPreKeys++;
      } else if (rawKey.startsWith('kem-one-time:')) {
        kemOneTimePreKeys++;
      }
    }

    return {
      sessions: await this.db!.count('sessions'),
      ecSignedPreKeys,
      ecOneTimePreKeys,
      kyberPreKeys,
      kemOneTimePreKeys,
      users: await this.db!.count('sesameUsers'),
    };
  }

  private getSenderKeyRecordStorageKey(groupId: string, userId: string, deviceId: number): string {
    return `${groupId}:${userId}:${deviceId}`;
  }

  private getSkippedSenderKeyPrefix(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): string {
    return `${groupId}:${senderId}:${senderDeviceId}`;
  }

  private getSkippedSenderKeyStorageKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): string {
    return `${this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId)}:${chainIndex}`;
  }

  private getMessageRecordStorageKey(sessionId: string, timestamp: number): string {
    return `${sessionId}:${timestamp}`;
  }
}
