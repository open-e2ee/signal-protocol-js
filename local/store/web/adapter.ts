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

import { utf8Decode } from '../../../internal/platform';
import type {
  MetadataKeyQuery,
  ReceiveWorkMetadataWrite,
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  ReceiveWorkUsage,
  SenderKeyReceiveCommit,
} from '../../../types';
import { openDB, IDBPDatabase, DBSchema } from 'idb';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';
import type {
  LocalStoreProtection,
  SignalProtocolLocalStore,
  MessageRecord,
  NewSendLogPayload,
  SendLogDevice,
  SendLogEntry,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
  SkippedSenderMessageKey,
  SessionTrustCommit,
  SenderKeyHandoffDevice,
  SenderKeyHandoffRecord,
  SenderKeyRecordWriteOptions,
  SetDeviceRecordOptions,
} from '../../../types';
import { getErrorMessage } from '../../../utils/errors';
import { generateRandomBytes } from '../../../internal/crypto/random';
import { decryptAes, encryptAes } from '../../../internal/crypto/symmetric/aes-provider';
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
import type { SessionState } from '../../../types';
import { ProtocolAddress } from '../../../types/address';
import { IdentityKeyChange, StorageQuotaExceededError, TrustDirection } from '../../../types';
import { assertCurrentSessionRecord, type SessionRecord } from '../../../types/session';
import type { UserRecord, DeviceRecord } from '../../../types';
import { isExpiredRemovedDevice } from '../../../internal/sesame/types';
import { withDeviceRecordLocks } from '../../../internal/session/record-locks';
import { withSession } from '../device-record';
import { decodeUserRecord, encodeUserRecord } from './device-record';
import {
  IndexedDbSendLog,
  SEND_LOG_STORE_NAMES,
  type SendLogDBSchema,
  upgradeSendLogStores,
} from './send-log';
import {
  IndexedDbReceiveWork,
  type ReceiveWorkDBSchema,
  upgradeReceiveWorkStore,
} from './receive-work';
import {
  IndexedDbSenderKeyHandoffs,
  type SenderKeyHandoffDBSchema,
  upgradeSenderKeyHandoffStore,
} from './sender-key-handoff';
import type { Base64 } from '../../../types/utils';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import { deserializeSessionRecord, serializeSessionRecord } from '../session-codec';
import { receivedContentKey } from '../received-content';
import { convertLegacyReceivedContent, type LegacyReceivedContentSource } from '../receive-work';
import { metadataKeyLimit } from '../metadata-keys';
import {
  createKyberPreKeyState,
  createKyberPreKeyInstanceId,
  getCurrentKyberPreKey,
  getRetainedKyberPreKey,
  recordKyberPreKeyUse,
  recordKyberPreKeyUseById,
  type RetainedKyberPreKey,
  retainKyberPreKey,
  type StoredKyberPreKeyState,
} from '../kyber-prekey-lifecycle';

function equalBytes(left: Uint8Array | undefined, right: Uint8Array | undefined): boolean {
  if (!left || !right) return left === right;
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

/**
 * The first byte of an encrypted metadata value. The record cipher's output
 * follows it. A metadata value stored as a string is a clear value that an
 * older SDK wrote.
 */
const METADATA_CIPHER_VERSION = 1;

/**
 * Set after every clear metadata value is encrypted. A crash before it is set
 * runs the migration again at the next open.
 */
const METADATA_CIPHER_MARKER_KEY = 'metadataCipherVersion';

function metadataStorageKey(key: string): string {
  return `meta:${key}`;
}

/** Compares two raw stored metadata values, clear or encrypted. */
function sameStoredMetadata(left: unknown, right: unknown): boolean {
  if (left instanceof Uint8Array && right instanceof Uint8Array) return equalBytes(left, right);
  return left === right;
}

/** The IndexedDB key of the sender key record of one sender in one group. */
type SenderKeyRecordId = [groupId: string, userId: string, deviceId: number];

/** The IndexedDB key of one sender in one group, for skipped sender keys. */
type SkippedSenderKeySender = [groupId: string, senderId: string, senderDeviceId: number];

/** The IndexedDB key of one skipped sender key. */
type SkippedSenderKeyId = [...SkippedSenderKeySender, senderKeyId: string, chainIndex: number];

/**
 * IndexedDB schema for Signal Protocol storage
 */
export {};
interface SignalProtocolDBSchema
  extends DBSchema,
    SendLogDBSchema,
    ReceiveWorkDBSchema,
    SenderKeyHandoffDBSchema {
  // Metadata store - contains database key and registration ID
  metadata: { key: string; value: Uint8Array | number | string };

  // Identity keys store - our own identity
  identity: { key: string; value: Uint8Array };

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

  // Sender key records (current + previous states) for group messaging. The
  // keys are arrays, so a group or user name that contains `:` cannot collide.
  senderKeyRecords: {
    key: SenderKeyRecordId;
    value: {
      key: SenderKeyRecordId;
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
    indexes: { 'by-group': string; 'by-sender-key-id': string };
  };

  // Skipped sender keys for out-of-order sender-key messages. The keys are
  // arrays, so a group or sender name that contains `:` cannot collide.
  skippedSenderKeys: {
    key: SkippedSenderKeyId;
    value: {
      key: SkippedSenderKeyId;
      groupId: string;
      senderKey: SkippedSenderKeySender;
      chainIndex: number;
      data: Uint8Array;
      createdAt: number;
    };
    indexes: { 'by-group': string; 'by-sender': SkippedSenderKeySender; 'by-created': number };
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
    indexes: { 'by-session': string; 'by-created': number };
  };
}

/**
 * The database as the send log types it. The schema extends
 * `SendLogDBSchema`, so the send log stores have the same types in both. The
 * idb types do not let a database with more stores stand in for one with
 * fewer.
 */
function sendLogView(db: IDBPDatabase<SignalProtocolDBSchema>): IDBPDatabase<SendLogDBSchema> {
  return db as unknown as IDBPDatabase<SendLogDBSchema>;
}

/** The database as the receive records type it, for the same reason as `sendLogView`. */
function receiveWorkView(
  db: IDBPDatabase<SignalProtocolDBSchema>
): IDBPDatabase<ReceiveWorkDBSchema> {
  return db as unknown as IDBPDatabase<ReceiveWorkDBSchema>;
}

/** The database as the sender-key handoff rows type it, for the same reason as `sendLogView`. */
function senderKeyHandoffView(
  db: IDBPDatabase<SignalProtocolDBSchema>
): IDBPDatabase<SenderKeyHandoffDBSchema> {
  return db as unknown as IDBPDatabase<SenderKeyHandoffDBSchema>;
}

/**
 * Run the reads and the mutations of one read-write transaction. `enter`
 * reads what it needs, then pushes every mutation in one synchronous batch:
 * a page that dies commits a transaction idle at an await, so an await
 * between two mutations could land only some of them. A failure aborts the
 * transaction, so no mutation of the batch commits.
 */
async function commitTransaction(
  tx: { abort(): void; readonly done: Promise<void> },
  enter: (writes: Promise<unknown>[]) => Promise<void> | void
): Promise<void> {
  const writes: Promise<unknown>[] = [];
  const completed = tx.done;
  void completed.catch(() => undefined);
  try {
    await enter(writes);
    await Promise.all([...writes, completed]);
  } catch (error) {
    try {
      tx.abort();
    } catch {
      /* The failed transaction can already be inactive. */
    }
    await Promise.allSettled([...writes, completed]);
    throw error;
  }
}

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
 * Implements SignalProtocolLocalStore for web browsers with:
 * - IndexedDB for persistent storage
 * - Web Crypto API for AES-256-GCM encryption
 * - All sensitive data encrypted at rest
 * - TOFU (Trust On First Use) for contact verification
 */
export class IndexedDbSignalProtocolStore implements SignalProtocolLocalStore {
  /** Each value is encrypted with a key that this database holds in the same origin. */
  readonly protection: LocalStoreProtection = Object.freeze({
    atRest: 'record-cipher',
    keyCustody: 'same-origin',
  });
  private db: IDBPDatabase<SignalProtocolDBSchema> | null = null;
  private databaseKey: Uint8Array | null = null;
  private readonly senderKeyHandoffs = new IndexedDbSenderKeyHandoffs(
    () => senderKeyHandoffView(this.db!),
    {
      encrypt: (plaintext) => this.encrypt(plaintext),
      decrypt: (encrypted) => this.decrypt(encrypted),
      databaseKey: () => this.getDatabaseKey(),
    }
  );
  private readonly dbName = 'signal-protocol-storage';
  /** The database name. The tabs and workers of the origin share its locks. */
  readonly storeIdentity: string = this.dbName;
  // v10 adds the sender-key handoff store. v11 adds `removedAt` to the
  // device record. The encrypted record holds the field, so v11 changes no
  // object store. It keeps an older SDK, which does not skip a removed
  // device, from opening the database.
  private readonly dbVersion = 11;
  private readonly sendLog = new IndexedDbSendLog(
    () => sendLogView(this.db!),
    {
      encrypt: (plaintext) => this.encrypt(plaintext),
      decrypt: (encrypted) => this.decrypt(encrypted),
    }
  );
  private readonly receiveWork = new IndexedDbReceiveWork(() => receiveWorkView(this.db!), {
    encrypt: (plaintext) => this.encrypt(plaintext),
    decrypt: (encrypted) => this.decrypt(encrypted),
    databaseKey: () => this.getDatabaseKey(),
  });

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
        // cannot be indexed retroactively without decrypting each one. Rows
        // written before v7 have `:`-joined keys that collide when a group or
        // user name contains `:`. The cost of dropping them is a round of
        // sender key redistribution, which the protocol already handles.
        if (oldVersion > 0 && oldVersion < 7 && db.objectStoreNames.contains('senderKeyRecords')) {
          db.deleteObjectStore('senderKeyRecords');
        }
        if (!db.objectStoreNames.contains('senderKeyRecords')) {
          const senderKeyStore = db.createObjectStore('senderKeyRecords', { keyPath: 'key' });
          senderKeyStore.createIndex('by-group', 'groupId');
          senderKeyStore.createIndex('by-sender-key-id', 'senderKeyIds', { multiEntry: true });
        }

        // Deleting a group deletes its skipped sender keys through a group
        // index. Rows written before v7 do not carry the group, and their
        // `:`-joined storage keys collide when a group or sender name
        // contains `:`. The cost of dropping them is that the messages they
        // were kept for no longer decrypt.
        if (oldVersion > 0 && oldVersion < 7 && db.objectStoreNames.contains('skippedSenderKeys')) {
          db.deleteObjectStore('skippedSenderKeys');
        }
        if (!db.objectStoreNames.contains('skippedSenderKeys')) {
          const skippedStore = db.createObjectStore('skippedSenderKeys', { keyPath: 'key' });
          skippedStore.createIndex('by-group', 'groupId');
          skippedStore.createIndex('by-sender', 'senderKey');
          skippedStore.createIndex('by-created', 'createdAt');
        }

        if (!db.objectStoreNames.contains('messageRecords')) {
          const messageStore = db.createObjectStore('messageRecords', { keyPath: 'key' });
          messageStore.createIndex('by-session', 'sessionId');
          messageStore.createIndex('by-created', 'createdAt');
        }

        upgradeSendLogStores(sendLogView(db));
        upgradeReceiveWorkStore(receiveWorkView(db));
        upgradeSenderKeyHandoffStore(senderKeyHandoffView(db));
      },
    });

    // Get or generate database encryption key
    const storedKey = await this.db.get('metadata', 'databaseKey');
    if (storedKey) {
      this.databaseKey = storedKey as Uint8Array;
    } else {
      // Generate a new 32-byte key from the secure random seam. The add() call refuses to
      // overwrite, so when two connections bootstrap a fresh database
      // concurrently, exactly one key is ever stored. The loser adopts the
      // winner's key instead of encrypting records nobody else can read.
      const candidate = await generateRandomBytes(32);
      try {
        await this.db.add('metadata', candidate, 'databaseKey');
        this.databaseKey = candidate;
      } catch (error) {
        if (!isConstraintError(error)) throw error;
        this.databaseKey = (await this.db.get('metadata', 'databaseKey')) as Uint8Array;
      }

      // ⚠️ WARNING: Browser storage is vulnerable to XSS attacks
      console.warn(
        '[IndexedDbSignalProtocolStore] Database encryption key stored in IndexedDB. ' +
          'Ensure Content Security Policy (CSP) is configured to mitigate XSS risks.'
      );
    }

    await this.encryptClearMetadata();
    await this.convertLegacyReceivedRows();
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
    const accountHash = (await this.senderKeyHandoffs.index()).account(address.userId);

    const tx = this.db!.transaction(['contacts', 'sessions', 'senderKeyHandoff'], 'readwrite');
    await commitTransaction(tx, async (writes) => {
      const contacts = tx.objectStore('contacts');
      const current = await contacts.get(key);
      if (!current || current.revision !== existing.revision) {
        throw new Error('Contact identity changed concurrently during rotation');
      }
      // Read the doomed session and handoff keys before mutating, then enter
      // every mutation in one synchronous batch. A cursor walk that deletes
      // as it goes leaves windows where the new pin commits with sessions
      // still trusted under the old identity.
      const sessions = tx.objectStore('sessions');
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedKeys = await sessions.index('by-user').getAllKeys(address.userId);
      const doomedHandoffs = await handoffs.index('by-account').getAllKeys(accountHash);
      writes.push(
        contacts.put({
          key,
          userId: address.userId,
          data: encrypted,
          revision: replacement.revision,
        })
      );
      // Push each request as it is created. A later synchronous throw must
      // not leave an earlier request outside the settled set.
      for (const sessionKey of doomedKeys) writes.push(sessions.delete(sessionKey));
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
    });
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
    const verified = verifyContactIdentityRecord(
      existing,
      identity,
      Date.now(),
      suppliedCommitment
    );
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
    const storageKey = `kyber:${it}`;
    const stored = await this.db!.get('prekeys', storageKey);
    const state = stored
      ? (JSON.parse(await this.decrypt(stored)) as StoredKyberPreKeyState)
      : createKyberPreKeyState();
    const instanceId = await createKyberPreKeyInstanceId();
    if (!retainKyberPreKey(state, kyberPreKey, it, Date.now(), instanceId)) return;
    const encrypted = await this.encrypt(JSON.stringify(state));
    const tx = this.db!.transaction('prekeys', 'readwrite');
    const prekeys = tx.objectStore('prekeys');
    if (!equalBytes(await prekeys.get(storageKey), stored)) {
      tx.abort();
      await tx.done.catch(() => undefined);
      throw new Error('Kyber prekey state changed during immutable store');
    }
    await Promise.all([prekeys.put(encrypted, storageKey), tx.done]);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('prekeys', `kyber:${it}`);
    if (!encrypted) return null;

    const decrypted = await this.decrypt(encrypted);
    return getCurrentKyberPreKey(JSON.parse(decrypted) as StoredKyberPreKeyState);
  }

  async getKyberPreKeyById(
    keyId: number,
    identityType?: IdentityType
  ): Promise<RetainedKyberPreKey | null> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('prekeys', `kyber:${it}`);
    if (!encrypted) return null;
    return getRetainedKyberPreKey(
      JSON.parse(await this.decrypt(encrypted)) as StoredKyberPreKeyState,
      keyId
    );
  }

  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';

    const storageKey = `kyber:${it}`;
    const stored = await this.db!.get('prekeys', storageKey);
    const state = stored
      ? (JSON.parse(await this.decrypt(stored)) as StoredKyberPreKeyState)
      : null;
    recordKyberPreKeyUseById(state, it, { kyberPreKeyId, signedPreKeyId, baseKeyBytes });
    const updated = await this.encrypt(JSON.stringify(state));
    const tx = this.db!.transaction('prekeys', 'readwrite');
    const prekeys = tx.objectStore('prekeys');
    if (!equalBytes(await prekeys.get(storageKey), stored)) {
      tx.abort();
      await tx.done.catch(() => undefined);
      throw new Error('Kyber prekey state changed during replay insertion');
    }
    await Promise.all([prekeys.put(updated, storageKey), tx.done]);
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
    const contactKey = this.serializeContactIdentityKey(commit.address, commit.contactIdentityType);
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
    const contactStatus = evaluateContactIdentityCandidate(existingContact, commit.contactIdentity);
    if (contactStatus !== 'NEW' && contactStatus !== 'MATCH') {
      throw new Error(
        `Atomic session/trust commit rejected contact identity status ${contactStatus}`
      );
    }
    const newContact =
      contactStatus === 'NEW'
        ? createUnverifiedContactIdentityRecord(commit.contactIdentity, Date.now())
        : null;
    const encryptedContact = newContact
      ? await this.encrypt(JSON.stringify(newContact))
      : undefined;
    const encrypted = await this.encrypt(serializeSessionRecord(commit.record));
    const work = commit.receiveWork ? await this.receiveWork.seal(commit.receiveWork) : undefined;
    const kyberStorageKey = `kyber:${commit.localIdentityType}`;
    const storedKyberState = commit.kyberPreKeyUse
      ? await this.db!.get('prekeys', kyberStorageKey)
      : undefined;
    let updatedKyberState: Uint8Array | undefined;
    if (commit.kyberPreKeyUse) {
      const state = storedKyberState
        ? (JSON.parse(await this.decrypt(storedKyberState)) as StoredKyberPreKeyState)
        : null;
      recordKyberPreKeyUse(state, commit.localIdentityType, commit.kyberPreKeyUse);
      updatedKyberState = await this.encrypt(JSON.stringify(state));
    }
    const invalidation = commit.senderKeyHandoffInvalidation;
    const invalidatedHash = invalidation
      ? (await this.senderKeyHandoffs.index()).recipient(invalidation)
      : undefined;
    const tx = this.db!.transaction(
      ['contacts', 'prekeys', 'sessions', 'receiveWork', 'senderKeyHandoff'],
      'readwrite'
    );
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
    if (
      commit.kyberPreKeyUse &&
      !equalBytes(await prekeys.get(kyberStorageKey), storedKyberState)
    ) {
      await tx.done;
      throw new Error('Kyber prekey state changed during atomic session/trust commit');
    }
    const handoffs = tx.objectStore('senderKeyHandoff');
    const doomedHandoffs =
      invalidatedHash === undefined
        ? []
        : await handoffs.index('by-recipient').getAllKeys(invalidatedHash);
    // Every mutation must enter the transaction in one synchronous batch.
    // A dying page closes its connection gracefully, and a transaction that
    // is idle at an await boundary then commits the writes it already holds.
    // An await between mutations is a window for a partial commit.
    const writes: Promise<unknown>[] = [];
    try {
      if (work) writes.push(tx.objectStore('receiveWork').put(work));
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
        tx
          .objectStore('sessions')
          .put({
            key: addressKey,
            userId: commit.address.userId,
            deviceId: commit.address.deviceId,
            data: encrypted,
            updatedAt: Date.now(),
          })
      );
      if (ecPreKeyStorageKey) writes.push(prekeys.delete(ecPreKeyStorageKey));
      if (kemPreKeyStorageKey) writes.push(prekeys.delete(kemPreKeyStorageKey));
      if (updatedKyberState) writes.push(prekeys.put(updatedKyberState, kyberStorageKey));
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
      await Promise.all([...writes, tx.done]);
    } catch (error) {
      try {
        tx.abort();
      } catch {
        /* The failed transaction can already be inactive. */
      }
      await Promise.allSettled([...writes, tx.done]);
      throw error;
    }
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    this.ensureInitialized();
    await this.replaceSessionAndDeleteHandoffs(address, null);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    this.ensureInitialized();

    // With SessionRecord, archiving is handled via SessionRecord.archiveCurrent()
    // This method updates or replaces the session state
    if (!newSession) {
      // If no new session, just delete the old one
      await this.replaceSessionAndDeleteHandoffs(address, null);
      return;
    }
    const record = await this.getSessionRecord(address);
    if (record) {
      // Update existing session with new state
      record.currentSession = newSession;
      if (record.metadata) {
        record.metadata.lastSentAt = Date.now();
      }
      assertCurrentSessionRecord(record);
    }
    await this.replaceSessionAndDeleteHandoffs(
      address,
      record ? await this.encrypt(serializeSessionRecord(record)) : undefined
    );
  }

  /**
   * Write or delete the session of one device and delete the handoff rows of
   * that device in every group, in one transaction. `null` deletes the
   * session, and `undefined` leaves it.
   */
  private async replaceSessionAndDeleteHandoffs(
    address: ProtocolAddress,
    encrypted: Uint8Array | null | undefined
  ): Promise<void> {
    const addressKey = this.serializeAddress(address);
    const recipientHash = (await this.senderKeyHandoffs.index()).recipient(address);
    const tx = this.db!.transaction(['sessions', 'senderKeyHandoff'], 'readwrite');
    await commitTransaction(tx, async (writes) => {
      const sessions = tx.objectStore('sessions');
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedHandoffs = await handoffs.index('by-recipient').getAllKeys(recipientHash);
      if (encrypted) {
        writes.push(
          sessions.put({
            key: addressKey,
            userId: address.userId,
            deviceId: address.deviceId,
            data: encrypted,
            updatedAt: Date.now(),
          })
        );
      } else if (encrypted === null) {
        writes.push(sessions.delete(addressKey));
      }
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
    });
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
    for (const name of SEND_LOG_STORE_NAMES) await this.db!.clear(name);
    await this.db!.clear('receiveWork');
    await this.db!.clear('senderKeyHandoff');

    // Generate new database encryption key after clearing
    this.databaseKey = await generateRandomBytes(32);
    await this.db!.put('metadata', this.databaseKey, 'databaseKey');
  }

  // ============================================================================
  // Metadata storage
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    this.ensureInitialized();
    return await this.openMetadataValue(await this.db!.get('metadata', metadataStorageKey(key)));
  }

  async setMetadata(key: string, value: string): Promise<void> {
    this.ensureInitialized();
    const sealed = await this.sealMetadataValue(value);
    await this.db!.put('metadata', sealed, metadataStorageKey(key));
  }

  async deleteMetadata(key: string): Promise<void> {
    this.ensureInitialized();
    await this.db!.delete('metadata', metadataStorageKey(key));
  }

  /**
   * IndexedDB orders string keys by UTF-16 code unit. In that order, the
   * keys with the prefix are one block that starts at the prefix. So the read
   * starts at the prefix, or after the cursor when that is later, and the
   * page ends at the first key without the prefix.
   */
  async listMetadataKeys(query: MetadataKeyQuery): Promise<string[]> {
    this.ensureInitialized();
    const limit = metadataKeyLimit(query);
    const prefix = metadataStorageKey(query.prefix);
    const range =
      query.after !== undefined && query.after >= query.prefix
        ? IDBKeyRange.lowerBound(metadataStorageKey(query.after), true)
        : IDBKeyRange.lowerBound(prefix);
    const keys = await this.db!.getAllKeys('metadata', range, limit);
    const end = keys.findIndex((key) => !key.startsWith(prefix));
    return (end === -1 ? keys : keys.slice(0, end)).map((key) =>
      key.slice(metadataStorageKey('').length)
    );
  }

  async compareAndSetMetadata(
    key: string,
    expected: string | null,
    value: string | null
  ): Promise<boolean> {
    this.ensureInitialized();
    const storageKey = metadataStorageKey(key);
    // The cipher is not an IndexedDB request, and an await on it would let
    // the transaction commit. So the decrypt and the encrypt run first. The
    // transaction then compares the raw value that was read, so a writer that
    // changed the value since that read fails the check.
    const observed = await this.db!.get('metadata', storageKey);
    if ((await this.openMetadataValue(observed)) !== expected) return false;
    const sealed = value === null ? null : await this.sealMetadataValue(value);
    const tx = this.db!.transaction('metadata', 'readwrite');
    try {
      if (!sameStoredMetadata(await tx.store.get(storageKey), observed)) {
        await tx.done;
        return false;
      }
      if (sealed === null) await tx.store.delete(storageKey);
      else await tx.store.put(sealed, storageKey);
      await tx.done;
      return true;
    } catch (error) {
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  /** Encrypt one metadata value with the record cipher, behind its version byte. */
  private async sealMetadataValue(value: string): Promise<Uint8Array> {
    const encrypted = await this.encrypt(value);
    const sealed = new Uint8Array(1 + encrypted.length);
    sealed[0] = METADATA_CIPHER_VERSION;
    sealed.set(encrypted, 1);
    return sealed;
  }

  /** Read one stored metadata value, encrypted or clear. */
  private async openMetadataValue(stored: unknown): Promise<string | null> {
    if (typeof stored === 'string') return stored;
    if (!(stored instanceof Uint8Array)) return null;
    if (stored[0] !== METADATA_CIPHER_VERSION) {
      throw new Error(`Unsupported metadata cipher version ${stored[0]}`);
    }
    return await this.decrypt(stored.subarray(1));
  }

  /**
   * Encrypt every clear metadata value, then set the marker. The marker is
   * set last, so a crash partway leaves it unset and the next open runs the
   * migration again. Each value is replaced only while it still holds the
   * clear value that was read, so a concurrent writer is never overwritten.
   *
   * A full origin stops the migration without the marker. The store still
   * opens, because a reader accepts clear values, and the next open
   * continues the migration.
   */
  private async encryptClearMetadata(): Promise<void> {
    const db = this.db!;
    if ((await db.get('metadata', METADATA_CIPHER_MARKER_KEY)) === METADATA_CIPHER_VERSION) return;
    const prefix = metadataStorageKey('');
    const keys = (await db.getAllKeys('metadata')).filter((key) => key.startsWith(prefix));
    try {
      for (const key of keys) {
        const stored = await db.get('metadata', key);
        if (typeof stored !== 'string') continue;
        const sealed = await this.sealMetadataValue(stored);
        const tx = db.transaction('metadata', 'readwrite');
        try {
          if ((await tx.store.get(key)) === stored) await tx.store.put(sealed, key);
          await tx.done;
        } catch (error) {
          await tx.done.catch(() => undefined);
          throw error;
        }
      }
      await db.put('metadata', METADATA_CIPHER_VERSION, METADATA_CIPHER_MARKER_KEY);
    } catch (error) {
      if (!isQuotaExceededError(error)) throw error;
    }
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

  private serializeContactIdentityKey(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): string {
    return `${address.userId}:${identityType ?? 'aci'}`;
  }

  private async decodeContactRecord(data: Uint8Array): Promise<ContactIdentityRecord> {
    const record = JSON.parse(await this.decrypt(data)) as ContactIdentityRecord;
    validateContactIdentityRecord(record);
    return record;
  }

  /**
   * Encrypt data using AES-256-GCM through the SDK AES provider
   *
   * @param plaintext - Data to encrypt
   * @returns IV (12 bytes) + ciphertext + auth tag (16 bytes)
   */
  private async encrypt(plaintext: string): Promise<Uint8Array> {
    if (!this.databaseKey) {
      throw new Error('Database key not available');
    }

    // Generate random IV (12 bytes for GCM)
    const iv = await generateRandomBytes(12);

    // Encode plaintext
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Encrypt
    const ciphertext = await encryptAes('AES-GCM', this.databaseKey, iv, data);

    // Combine IV + ciphertext (the auth tag ends the AES-GCM ciphertext)
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(ciphertext, 12);

    return result;
  }

  /**
   * Decrypt data using AES-256-GCM through the SDK AES provider
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

    // Decrypt
    try {
      const plaintext = await decryptAes('AES-GCM', this.databaseKey, iv, ciphertext);

      // Decode plaintext
      return utf8Decode(new Uint8Array(plaintext));
    } catch (error) {
      throw new Error(`Decryption failed: ${getErrorMessage(error)}`);
    }
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================

  // A device's session lives only in the `sessions` store; see `./device-record`.
  async getUserRecord(userId: string): Promise<UserRecord | null> {
    const record = await this.getStoredUserRecord(userId);
    if (!record) return null;
    for (const [deviceId, device] of record.devices) {
      const session = await this.getSessionRecord(ProtocolAddress.create(userId, deviceId));
      record.devices.set(deviceId, withSession(userId, deviceId, device, session)!);
    }
    return record;
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(encodeUserRecord(record)));
    await this.db!.put('sesameUsers', { key: userId, data: encrypted, updatedAt: Date.now() });
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    const stored = (await this.getStoredUserRecord(userId))?.devices.get(deviceId) ?? null;
    const session = await this.getSessionRecord(ProtocolAddress.create(userId, deviceId));
    return withSession(userId, deviceId, stored, session);
  }

  async setDeviceRecord(
    userId: string,
    deviceId: number,
    record: DeviceRecord,
    options?: SetDeviceRecordOptions
  ): Promise<void> {
    if (record.session) assertCurrentSessionRecord(record.session);
    const now = Date.now();
    const userRecord = (await this.getStoredUserRecord(userId)) ?? {
      userId,
      devices: new Map(),
      createdAt: now,
      updatedAt: now,
    };
    userRecord.devices.set(deviceId, record);
    userRecord.updatedAt = now;

    // Encryption awaits Web Crypto, so it finishes before the transaction
    // opens. Both writes then enter the transaction in one synchronous batch.
    const user = await this.encrypt(JSON.stringify(encodeUserRecord(userRecord)));
    const session = record.session
      ? await this.encrypt(serializeSessionRecord(record.session))
      : null;
    const invalidation = options?.senderKeyHandoffInvalidation;
    const invalidatedHash = invalidation
      ? (await this.senderKeyHandoffs.index()).recipient(invalidation)
      : undefined;
    const tx = this.db!.transaction(['sesameUsers', 'sessions', 'senderKeyHandoff'], 'readwrite');
    await commitTransaction(tx, async (writes) => {
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedHandoffs =
        invalidatedHash === undefined
          ? []
          : await handoffs.index('by-recipient').getAllKeys(invalidatedHash);
      writes.push(tx.objectStore('sesameUsers').put({ key: userId, data: user, updatedAt: now }));
      if (session) {
        writes.push(
          tx.objectStore('sessions').put({
            key: this.serializeAddress(ProtocolAddress.create(userId, deviceId)),
            userId,
            deviceId,
            data: session,
            updatedAt: now,
          })
        );
      }
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
    });
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    const now = Date.now();
    const userRecord = await this.getStoredUserRecord(userId);
    userRecord?.devices.delete(deviceId);
    const user =
      userRecord && userRecord.devices.size > 0
        ? await this.encrypt(JSON.stringify(encodeUserRecord({ ...userRecord, updatedAt: now })))
        : null;

    // A device can exist through its session alone, so the session goes even
    // when no stored user record names the device.
    const sessionKey = this.serializeAddress(ProtocolAddress.create(userId, deviceId));
    const recipientHash = (await this.senderKeyHandoffs.index()).recipient({ userId, deviceId });
    const tx = this.db!.transaction(['sesameUsers', 'sessions', 'senderKeyHandoff'], 'readwrite');
    await commitTransaction(tx, async (writes) => {
      const users = tx.objectStore('sesameUsers');
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedHandoffs = await handoffs.index('by-recipient').getAllKeys(recipientHash);
      writes.push(tx.objectStore('sessions').delete(sessionKey));
      if (user) writes.push(users.put({ key: userId, data: user, updatedAt: now }));
      else if (userRecord) writes.push(users.delete(userId));
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
    });
  }

  private async getStoredUserRecord(userId: string): Promise<UserRecord | null> {
    this.ensureInitialized();
    const entry = await this.db!.get('sesameUsers', userId);
    if (!entry) return null;
    return decodeUserRecord(JSON.parse(await this.decrypt(entry.data)));
  }

  async deleteStaleRecords(maxLatency: number): Promise<number> {
    this.ensureInitialized();

    const now = Date.now();
    let deletedCount = 0;

    // The scan takes no lock. Each device is decided again under the locks of
    // its records, so a write that lands after the scan is kept.
    for (const userId of await this.getAllUserIds()) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      for (const [deviceId, deviceRecord] of userRecord.devices) {
        if (!isStaleDeviceRecord(deviceRecord, now, maxLatency)) continue;
        const deleted = await withDeviceRecordLocks(this, userId, deviceId, async () => {
          const current = await this.getDeviceRecord(userId, deviceId);
          if (!current || !isStaleDeviceRecord(current, now, maxLatency)) return false;
          await this.deleteDeviceRecord(userId, deviceId);
          return true;
        });
        if (deleted) deletedCount++;
      }
    }

    return deletedCount;
  }

  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    this.ensureInitialized();

    const now = Date.now();
    let deletedCount = 0;

    // The scan takes no lock. Each session is decided again under the locks
    // of its device, so a session that is written after the scan is kept.
    for (const userId of await this.getAllUserIds()) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      for (const [deviceId, deviceRecord] of userRecord.devices) {
        if (!deviceRecord.session) continue;
        deletedCount += await withDeviceRecordLocks(this, userId, deviceId, async () => {
          const current = await this.getDeviceRecord(userId, deviceId);
          if (!current) return 0;
          const deleted = expireDeviceSessions(current, now, maxRecv);
          if (deleted > 0) {
            current.updatedAt = Date.now();
            await this.setDeviceRecord(userId, deviceId, current);
          }
          return deleted;
        });
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
    const userRecord = await this.getStoredUserRecord(userId);
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

  async deleteSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void> {
    this.ensureInitialized();
    if (!options?.deleteSenderKeyHandoffs) {
      await this.db!.delete('senderKeyRecords', [groupId, userId, deviceId]);
      return;
    }
    const groupHash = (await this.senderKeyHandoffs.index()).group(groupId);
    const tx = this.db!.transaction(['senderKeyRecords', 'senderKeyHandoff'], 'readwrite');
    await commitTransaction(tx, async (writes) => {
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedHandoffs = await handoffs.index('by-group').getAllKeys(groupHash);
      writes.push(tx.objectStore('senderKeyRecords').delete([groupId, userId, deviceId]));
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
    });
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

    // Read the doomed keys before mutating, then enter every delete in one
    // synchronous batch, so the sender keys, the skipped keys, and the
    // handoff rows go together.
    const groupHash = (await this.senderKeyHandoffs.index()).group(groupId);
    const tx = this.db!.transaction(
      ['senderKeyRecords', 'skippedSenderKeys', 'senderKeyHandoff'],
      'readwrite'
    );
    let deleted = 0;
    await commitTransaction(tx, async (writes) => {
      const senderKeyRecords = tx.objectStore('senderKeyRecords');
      const skippedSenderKeys = tx.objectStore('skippedSenderKeys');
      const handoffs = tx.objectStore('senderKeyHandoff');
      const [recordKeys, skippedKeys, handoffKeys] = await Promise.all([
        senderKeyRecords.index('by-group').getAllKeys(groupId),
        skippedSenderKeys.index('by-group').getAllKeys(groupId),
        handoffs.index('by-group').getAllKeys(groupHash),
      ]);
      deleted = recordKeys.length;
      // Push each request as it is created. A later synchronous throw must
      // not leave an earlier request outside the settled set.
      for (const key of recordKeys) writes.push(senderKeyRecords.delete(key));
      for (const key of skippedKeys) writes.push(skippedSenderKeys.delete(key));
      for (const key of handoffKeys) writes.push(handoffs.delete(key));
    });
    return deleted;
  }

  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[],
    receive?: SenderKeyReceiveCommit,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void> {
    this.ensureInitialized();
    if (states.length === 0) {
      return;
    }

    const encrypted = await this.encrypt(JSON.stringify(states));
    const work = receive?.work ? await this.receiveWork.seal(receive.work) : undefined;
    // Finish encryption before opening the IDB transaction, which must not await crypto.
    const skippedKeys = await Promise.all(
      (receive?.skippedKeys?.keys ?? []).map(async (skipped) => ({
        key: this.getSkippedSenderKeyStorageKey(
          groupId,
          userId,
          deviceId,
          skipped.senderKeyId,
          skipped.chainIndex
        ),
        groupId,
        senderKey: this.getSkippedSenderKeyPrefix(groupId, userId, deviceId),
        chainIndex: skipped.chainIndex,
        data: await this.encrypt(JSON.stringify(skipped.messageKey)),
        createdAt: Date.now(),
      }))
    );
    const deletedGroupHash = options?.deleteSenderKeyHandoffs
      ? (await this.senderKeyHandoffs.index()).group(groupId)
      : undefined;
    const tx = this.db!.transaction(
      ['senderKeyRecords', 'skippedSenderKeys', 'receiveWork', 'senderKeyHandoff'],
      'readwrite'
    );
    // Observe aborts immediately, including while the skipped-key read is pending.
    const completed = tx.done;
    void completed.catch(() => undefined);
    const writes: Promise<unknown>[] = [];
    try {
      const skippedStore = tx.objectStore('skippedSenderKeys');
      // Read this sender's skipped keys once and plan every eviction in
      // memory. Then enter all writes in one synchronous batch: a page that
      // dies commits a transaction idle at an await, so an await between two
      // writes could land only some of them.
      const resident =
        skippedKeys.length > 0
          ? (
              await skippedStore
                .index('by-sender')
                .getAll(this.getSkippedSenderKeyPrefix(groupId, userId, deviceId))
            ).map(({ key, chainIndex }) => ({ key, chainIndex }))
          : [];
      const handoffs = tx.objectStore('senderKeyHandoff');
      const doomedHandoffs =
        deletedGroupHash === undefined
          ? []
          : await handoffs.index('by-group').getAllKeys(deletedGroupHash);
      const sameKey = (a: SkippedSenderKeyId, b: SkippedSenderKeyId) =>
        a.every((part, index) => part === b[index]);
      const skippedWrites: Array<
        { put: (typeof skippedKeys)[number] } | { delete: SkippedSenderKeyId }
      > = [];
      for (const skipped of skippedKeys) {
        resident.sort((a, b) => a.chainIndex - b.chainIndex);
        const count = resident.length - Math.max(0, receive!.skippedKeys!.maxSkippedKeys - 1);
        for (const old of resident.splice(0, Math.max(0, count))) {
          skippedWrites.push({ delete: old.key });
        }
        const replaced = resident.findIndex((entry) => sameKey(entry.key, skipped.key));
        if (replaced !== -1) resident.splice(replaced, 1);
        resident.push({ key: skipped.key, chainIndex: skipped.chainIndex });
        skippedWrites.push({ put: skipped });
      }
      if (receive?.consumedSkippedKey !== undefined) {
        skippedWrites.push({
          delete: this.getSkippedSenderKeyStorageKey(
            groupId,
            userId,
            deviceId,
            receive.consumedSkippedKey.senderKeyId,
            receive.consumedSkippedKey.chainIndex
          ),
        });
      }

      writes.push(
        tx.objectStore('senderKeyRecords').put({
          key: [groupId, userId, deviceId],
          groupId,
          userId,
          deviceId,
          // Include archived IDs so delayed messages still resolve to this group.
          senderKeyIds: states.map((state) => state.senderKeyId).filter(Boolean),
          data: encrypted,
          updatedAt: Date.now(),
        })
      );
      for (const write of skippedWrites) {
        writes.push(
          'put' in write ? skippedStore.put(write.put) : skippedStore.delete(write.delete)
        );
      }
      if (work) writes.push(tx.objectStore('receiveWork').put(work));
      for (const handoffKey of doomedHandoffs) writes.push(handoffs.delete(handoffKey));
      await Promise.all([...writes, completed]);
    } catch (error) {
      try {
        tx.abort();
      } catch {
        /* The failed transaction can already be inactive. */
      }
      await Promise.allSettled([...writes, completed]);
      throw error;
    }
  }

  // ============================================================================
  // Sender-Key Handoff Ledger
  // ============================================================================

  async recordSenderKeyHandoff(record: SenderKeyHandoffRecord): Promise<void> {
    this.ensureInitialized();
    await this.senderKeyHandoffs.record(record);
  }

  async listSenderKeyHandoffs(
    groupId: string,
    generation: number
  ): Promise<SenderKeyHandoffRecord[]> {
    this.ensureInitialized();
    return this.senderKeyHandoffs.list(groupId, generation);
  }

  async invalidateSenderKeyHandoff(
    groupId: string,
    device: SenderKeyHandoffDevice
  ): Promise<boolean> {
    this.ensureInitialized();
    return this.senderKeyHandoffs.deleteDeviceInGroup(groupId, device);
  }

  async invalidateAccountSenderKeyHandoffs(userId: string): Promise<boolean> {
    this.ensureInitialized();
    return this.senderKeyHandoffs.deleteAccount(userId);
  }

  async listSenderKeyHandoffGroupIds(): Promise<string[]> {
    this.ensureInitialized();
    return this.senderKeyHandoffs.groupIds();
  }

  async retainSenderKeyHandoffs(groupId: string, senderKeyId: string | null): Promise<number> {
    this.ensureInitialized();
    return this.senderKeyHandoffs.retain(groupId, senderKeyId);
  }

  // ============================================================================
  // Receive records
  // ============================================================================

  async getReceiveWork(workId: string): Promise<ReceiveWorkRecord | null> {
    this.ensureInitialized();
    return await this.receiveWork.get(workId);
  }

  async putReceiveWork(
    record: ReceiveWorkRecord,
    expectedRevision: number | null
  ): Promise<boolean> {
    this.ensureInitialized();
    return await this.receiveWork.put(record, expectedRevision);
  }

  async listReceiveWork(query?: ReceiveWorkQuery): Promise<ReceiveWorkRecord[]> {
    this.ensureInitialized();
    return await this.receiveWork.list(query);
  }

  async receiveWorkUsage(query?: { groupId?: string }): Promise<ReceiveWorkUsage> {
    this.ensureInitialized();
    return await this.receiveWork.usage(query);
  }

  async completeReceiveWork(
    workId: string,
    expectedRevision: number,
    metadata: readonly ReceiveWorkMetadataWrite[] = []
  ): Promise<boolean> {
    this.ensureInitialized();
    // Seal every metadata value first: the transaction must not await the cipher.
    const metadataWrites = await Promise.all(
      metadata.map(async ({ key, value }) => ({
        storageKey: metadataStorageKey(key),
        sealed: value === null ? null : await this.sealMetadataValue(value),
      }))
    );
    const tx = this.db!.transaction(['receiveWork', 'metadata'], 'readwrite');
    const completed = tx.done;
    void completed.catch(() => undefined);
    const writes: Promise<unknown>[] = [];
    try {
      const records = tx.objectStore('receiveWork');
      const current = await records.get(workId);
      if (current?.revision !== expectedRevision) {
        await completed;
        return false;
      }
      // Enter the delete and every metadata write in one synchronous batch.
      const metadataStore = tx.objectStore('metadata');
      writes.push(records.delete(workId));
      for (const { storageKey, sealed } of metadataWrites) {
        writes.push(
          sealed === null ? metadataStore.delete(storageKey) : metadataStore.put(sealed, storageKey)
        );
      }
      await Promise.all([...writes, completed]);
      return true;
    } catch (error) {
      try {
        tx.abort();
      } catch {
        /* The failed transaction can already be inactive. */
      }
      await Promise.allSettled([...writes, completed]);
      throw error;
    }
  }

  /**
   * Convert the legacy received content rows to receive records. A full
   * origin stops the conversion without its marker. The store still opens,
   * and the next open continues the conversion.
   */
  private async convertLegacyReceivedRows(): Promise<void> {
    try {
      await convertLegacyReceivedContent(this, this.legacyReceivedContent());
    } catch (error) {
      if (!isQuotaExceededError(error) && !(error instanceof StorageQuotaExceededError)) {
        throw error;
      }
    }
  }

  /** The legacy rows: raw metadata keys `received-content:<id>`, each value from the record cipher. */
  private legacyReceivedContent(): LegacyReceivedContentSource {
    const prefix = receivedContentKey('');
    return {
      listIds: async () =>
        (await this.db!.getAllKeys('metadata'))
          .filter((key) => key.startsWith(prefix))
          .map((key) => key.slice(prefix.length)),
      read: async (id) => {
        const value = await this.db!.get('metadata', receivedContentKey(id));
        if (value === undefined) return null;
        if (!(value instanceof Uint8Array)) throw new Error('Invalid encrypted received content');
        return await this.decrypt(value);
      },
      delete: async (id) => {
        await this.db!.delete('metadata', receivedContentKey(id));
      },
    };
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    this.ensureInitialized();
    const stored = await this.db!.get('senderKeyRecords', [groupId, userId, deviceId]);
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
    senderKeyId: string,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(messageKey));
    await this.db!.put('skippedSenderKeys', {
      key: this.getSkippedSenderKeyStorageKey(
        groupId,
        senderId,
        senderDeviceId,
        senderKeyId,
        chainIndex
      ),
      groupId,
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
    senderKeyId: string,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null> {
    this.ensureInitialized();
    const stored = await this.db!.get(
      'skippedSenderKeys',
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, senderKeyId, chainIndex)
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
    senderKeyId: string,
    chainIndex: number
  ): Promise<void> {
    this.ensureInitialized();
    await this.db!.delete(
      'skippedSenderKeys',
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, senderKeyId, chainIndex)
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
    const matches: Array<{ key: SkippedSenderKeyId; chainIndex: number }> = [];
    const tx = this.db!.transaction('skippedSenderKeys', 'readonly');
    const index = tx.objectStore('skippedSenderKeys').index('by-sender');

    for await (const cursor of index.iterate(
      this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId)
    )) {
      matches.push({ key: cursor.primaryKey, chainIndex: cursor.value.chainIndex });
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
    const key = this.getMessageRecordStorageKey(record.sessionId, record.timestamp);
    const createdAt = (await this.db!.get('messageRecords', key))?.createdAt ?? Date.now();
    const encrypted = await this.encrypt(JSON.stringify({ ...record, createdAt }));
    await this.db!.put('messageRecords', {
      key,
      sessionId: record.sessionId,
      timestamp: record.timestamp,
      createdAt,
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

  /**
   * The records decrypt and encrypt outside a transaction, because IndexedDB
   * commits an idle transaction. The write transaction then changes a record
   * only when its stored bytes still equal the bytes that `rewrite` read.
   */
  async rewriteMessageRecords(rewrite: (record: MessageRecord) => string | null): Promise<number> {
    this.ensureInitialized();
    const selected: Array<{ key: string; data: Uint8Array; replacement: Uint8Array | null }> = [];
    for (const stored of await this.db!.getAll('messageRecords')) {
      const record = JSON.parse(await this.decrypt(stored.data)) as MessageRecord;
      const plaintext = rewrite(record);
      if (plaintext === record.plaintext) continue;
      const replacement =
        plaintext === null ? null : await this.encrypt(JSON.stringify({ ...record, plaintext }));
      selected.push({ key: stored.key, data: stored.data, replacement });
    }
    if (selected.length === 0) return 0;

    const tx = this.db!.transaction('messageRecords', 'readwrite');
    const store = tx.objectStore('messageRecords');
    let changed = 0;
    for (const { key, data, replacement } of selected) {
      const current = await store.get(key);
      if (!current || !encryptedBytesEqual(current.data, data)) continue;
      if (replacement === null) {
        await store.delete(key);
      } else {
        await store.put({ ...current, data: replacement });
      }
      changed++;
    }
    await tx.done;
    return changed;
  }

  // ============================================================================
  // Send Log (resendable group content)
  // The send log concept lives in ./send-log.ts. This store implements the
  // whole local store interface, so it keeps these delegates.
  // ============================================================================

  async storeSendLogEntry(
    payload: NewSendLogPayload,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    this.ensureInitialized();
    return this.sendLog.storeSendLogEntry(payload, recipients);
  }

  async appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    this.ensureInitialized();
    return this.sendLog.appendSendLogRecipients(clientMessageId, recipients);
  }

  async markSendLogComplete(clientMessageId: string): Promise<void> {
    this.ensureInitialized();
    return this.sendLog.markSendLogComplete(clientMessageId);
  }

  async getSendLogEntry(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<SendLogEntry | null> {
    this.ensureInitialized();
    return this.sendLog.getSendLogEntry(clientMessageId, recipient);
  }

  async findSendLogEntries(
    recipient: SendLogDevice,
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    this.ensureInitialized();
    return this.sendLog.findSendLogEntries(recipient, clientTimestamp);
  }

  async getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    this.ensureInitialized();
    return this.sendLog.getSendLogRecipients(clientMessageId);
  }

  async deleteSendLogRecipient(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<boolean> {
    this.ensureInitialized();
    return this.sendLog.deleteSendLogRecipient(clientMessageId, recipient);
  }

  async deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    this.ensureInitialized();
    return this.sendLog.deleteSendLogRecipientsByTimestamp(recipient, clientTimestamps);
  }

  async incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    this.ensureInitialized();
    return this.sendLog.incrementSendLogResendCount(clientMessageId, recipient);
  }

  async deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    this.ensureInitialized();
    return this.sendLog.deleteSendLogEntry(clientMessageId);
  }

  async deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    this.ensureInitialized();
    return this.sendLog.deleteExpiredSendLog(maxAgeMs);
  }

  async clearSendLog(): Promise<number> {
    this.ensureInitialized();
    return this.sendLog.clearSendLog();
  }

  async storeResendJob(job: SendLogResendJob): Promise<void> {
    this.ensureInitialized();
    return this.sendLog.storeResendJob(job);
  }

  async getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    this.ensureInitialized();
    return this.sendLog.getResendJob(jobId);
  }

  async getPendingResendJobs(): Promise<SendLogResendJob[]> {
    this.ensureInitialized();
    return this.sendLog.getPendingResendJobs();
  }

  async completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    this.ensureInitialized();
    return this.sendLog.completeResendJob(jobId, state);
  }

  // ============================================================================
  // Key Recovery Methods (Bug #7 - Identifier Collision Recovery)
  // ============================================================================

  async getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    const prekeys = await this.getAllEcSignedPreKeys(identityType);
    return prekeys.reduce((max, prekey) => Math.max(max, prekey.keyId), 0);
  }

  async getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    this.ensureInitialized();
    const it = identityType ?? 'aci';
    const encrypted = await this.db!.get('prekeys', `kyber:${it}`);
    if (!encrypted) return 0;
    const state = JSON.parse(await this.decrypt(encrypted)) as StoredKyberPreKeyState;
    return Object.keys(state.instances).reduce((max, id) => Math.max(max, Number(id)), 0);
  }

  async deleteAllPreKeys(
    identityType?: IdentityType
  ): Promise<{
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

  private getSkippedSenderKeyPrefix(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): SkippedSenderKeySender {
    return [groupId, senderId, senderDeviceId];
  }

  private getSkippedSenderKeyStorageKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
    chainIndex: number
  ): SkippedSenderKeyId {
    return [groupId, senderId, senderDeviceId, senderKeyId, chainIndex];
  }

  private getMessageRecordStorageKey(sessionId: string, timestamp: number): string {
    return `${sessionId}:${timestamp}`;
  }
}

/**
 * A device record is stale when it has no current session and no archived
 * session, and it has not been updated within `maxLatency`, or when its
 * removal is older than `maxLatency`.
 */
function isStaleDeviceRecord(record: DeviceRecord, now: number, maxLatency: number): boolean {
  const hasNoSessions =
    !record.session ||
    (!record.session.currentSession && Object.keys(record.session.archivedSessions).length === 0);
  return (
    (hasNoSessions && now - record.updatedAt > maxLatency) ||
    isExpiredRemovedDevice(record, now, maxLatency)
  );
}

/**
 * Delete the sessions of `record` that are older than `maxRecv`, and return
 * how many it deleted. The age of the current session comes from the session
 * metadata when it has a creation time.
 */
function expireDeviceSessions(record: DeviceRecord, now: number, maxRecv: number): number {
  const session = record.session;
  if (!session) return 0;
  let deleted = 0;

  if (session.currentSession) {
    const createdAt = session.metadata?.createdAt ?? session.currentSession.createdAt;
    if (now - createdAt > maxRecv) {
      session.currentSession = null;
      deleted++;
    }
  }

  for (const baseKey of Object.keys(session.archivedSessions) as Base64[]) {
    const archived = session.archivedSessions[baseKey];
    if (archived && now - archived.createdAt > maxRecv) {
      delete session.archivedSessions[baseKey];
      deleted++;
    }
  }

  return deleted;
}
