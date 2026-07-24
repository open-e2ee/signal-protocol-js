/**
 * React Native Storage Adapter (Bare Workflow)
 *
 * Storage adapter for React Native applications without Expo.
 * Uses:
 * - a caller-provided persistent key-value backend
 * - expo-crypto for secure random number generation
 * - Signal Protocol crypto module for AES-256-GCM encryption (via Web Crypto API)
 *
 * Security Considerations:
 * - All sensitive data encrypted with AES-256-GCM (128-bit auth tag)
 * - Database encryption key stored in the provided key-value backend
 * - For production apps, keep the database key in a platform secret vault
 * - Requires a Web Crypto API polyfill (e.g., react-native-quick-crypto) for bare RN
 *
 * @example
 * ```typescript
 * const keyValueStorage = yourPersistentKeyValueStorage;
 * const storage = await ReactNativeSignalStore.create({ storage: keyValueStorage });
 *
 * // Store identity key
 * await storage.storeIdentityKey(keyPair);
 * ```
 */

import * as Crypto from 'expo-crypto';
import * as SignalCrypto from '../../../internal/crypto';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';
import type {
  ISignalLocalStore,
  MessageRecord,
  UserRecord,
  DeviceRecord,
  SkippedSenderMessageKey,
  SessionTrustCommit,
} from '../../../types';
import {
  assertCurrentSessionRecord,
  type SessionRecord,
} from '../../../types/session';
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
import type { SessionState, ProtocolAddress, DeviceID } from '../../../types';
import { IdentityKeyChange, TrustDirection } from '../../../types';
import type { Base64 } from '../../../types/utils';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import type { ReactNativeKeyValueStorage } from './storage';
import { deserializeSessionRecord, serializeSessionRecord } from '../session-codec';

/**
 * Storage keys for the injected key-value backend
 */
export {};
const STORAGE_KEYS = {
  DATABASE_KEY: '@signal:databaseKey',
  IDENTITY_KEY_PREFIX: '@signal:identity:keyPair:',
  REGISTRATION_ID_PREFIX: '@signal:metadata:registrationId:',
  METADATA_PREFIX: '@signal:metadata:value:',
  CONTACT_PREFIX: '@signal:contacts:',
  CONTACT_V1_PREFIX: '@signal:contacts:v1:',
  PREKEY_PREFIX: '@signal:prekeys:',
  SESSION_PREFIX: '@signal:sessions:',
  SESAME_USER_PREFIX: '@signal:sesame:user:',
  SENDER_KEY_RECORD_PREFIX: '@signal:sender-key-record:',
  SKIPPED_SENDER_KEY_PREFIX: '@signal:skipped-sender-key:',
  MESSAGE_RECORD_PREFIX: '@signal:message-record:',
  SECURITY_EVENTS: '@signal:security-events',
} as const;

/**
 * Session storage record
 */
interface StoredSessionRecord {
  userId: string;
  deviceId: number;
  data: string; // Base64 encrypted SessionRecord
  updatedAt: number;
}

type SerializedUserRecord = Omit<UserRecord, 'devices'> & {
  devices: Array<[DeviceID, DeviceRecord]>;
};

/**
 * Security event record
 */
interface SecurityEvent {
  type: string;
  userId: string;
  deviceId?: number;
  oldKey?: string;
  newKey?: string;
  detectedAt: number;
}

/**
 * React Native storage adapter implementation
 *
 * Provides secure storage for Signal Protocol keys using an injected
 * React Native key-value backend and expo-crypto.
 *
 * @example
 * ```typescript
 * const keyValueStorage = yourPersistentKeyValueStorage;
 * const storage = await ReactNativeSignalStore.create({ storage: keyValueStorage });
 *
 * // Store identity key
 * await storage.storeIdentityKey(keyPair);
 *
 * // Get identity key
 * const keyPair = await storage.getIdentityKey();
 * ```
 */
export class ReactNativeSignalStore implements ISignalLocalStore {
  private databaseKey: Uint8Array | null = null;
  private initialized = false;
  private readonly _metadata = new Map<string, string>();
  private readonly storageBackend: ReactNativeKeyValueStorage;

  private constructor(options: { storage: ReactNativeKeyValueStorage }) {
    this.storageBackend = options.storage;
  }

  static async create(options: {
    storage: ReactNativeKeyValueStorage;
  }): Promise<ReactNativeSignalStore> {
    const store = new ReactNativeSignalStore(options);
    await store.initialize();
    return store;
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  /**
   * Initialize the storage adapter
   *
   * - Loads or generates database encryption key
   * - Stores key in the configured key-value backend
   */
  private async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Get or generate database encryption key
    const storedKey = await this.storageBackend.getItem(STORAGE_KEYS.DATABASE_KEY);
    if (storedKey) {
      // Decode from base64
      this.databaseKey = this.base64ToUint8Array(storedKey);
    } else {
      // Generate new 32-byte key
      this.databaseKey = Crypto.getRandomBytes(32);
      // Store as base64
      await this.storageBackend.setItem(
        STORAGE_KEYS.DATABASE_KEY,
        this.uint8ArrayToBase64(this.databaseKey)
      );

      console.warn(
        '[ReactNativeSignalStore] Database encryption key stored in the configured React Native storage backend. ' +
          'For production apps, configure a platform secret vault for database-key custody.'
      );
    }

    this.initialized = true;
  }

  /**
   * Get the database encryption key
   *
   * @returns 32-byte AES-256 key
   * @throws Error if not initialized
   */
  async getDatabaseKey(): Promise<Uint8Array> {
    this.ensureInitialized();
    return this.databaseKey!;
  }

  // ============================================================================
  // Identity Key Management - Own Keys
  // ============================================================================

  async storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(keyPair));
    await this.storageBackend.setItem(this.getIdentityKeyStorageKey(identityType), encrypted);
  }

  async getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getIdentityKeyStorageKey(identityType)
    );
    if (!encrypted) return null;

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async hasIdentityKey(identityType?: IdentityType): Promise<boolean> {
    this.ensureInitialized();
    const key = await this.storageBackend.getItem(this.getIdentityKeyStorageKey(identityType));
    return key !== null;
  }

  async getLocalRegistrationId(identityType?: IdentityType): Promise<number> {
    this.ensureInitialized();
    const id = await this.storageBackend.getItem(this.getRegistrationIdStorageKey(identityType));
    if (!id) return 0;
    return parseInt(id, 10);
  }

  async setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    await this.storageBackend.setItem(
      this.getRegistrationIdStorageKey(identityType),
      id.toString()
    );
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
    const storageKey = this.getContactStorageKey(address, identityType);
    const existing = await this.readContactRecord(address, identityType);
    const status = evaluateContactIdentityCandidate(existing, identity, suppliedCommitment);
    if (status === 'NEW') {
      await this.writeContactRecord(
        storageKey,
        createUnverifiedContactIdentityRecord(identity, Date.now())
      );
      return IdentityKeyChange.NEW_IDENTITY;
    }
    if (status === 'MATCH') return IdentityKeyChange.UNCHANGED;
    if (status === 'ROLLBACK') return IdentityKeyChange.ROLLBACK;
    return IdentityKeyChange.CHANGED;
  }

  async getContactIdentity(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): Promise<ContactIdentityRecord | null> {
    this.ensureInitialized();
    return await this.readContactRecord(address, identityType);
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
    const contactKey = this.getContactStorageKey(address, identityType);
    const existingValue = await this.storageBackend.getItem(contactKey);
    if (!existingValue) throw new Error('Cannot rotate an unseen identity');
    const existing = JSON.parse(await this.decrypt(existingValue)) as ContactIdentityRecord;
    validateContactIdentityRecord(existing);
    const replacement = acceptRotation(existing, identity, Date.now(), suppliedCommitment);
    validateContactIdentityRecord(replacement);
    await this.storageBackend.atomicWrite([
      { type: 'check', key: contactKey, expectedValue: existingValue },
      {
        type: 'set',
        key: contactKey,
        value: await this.encrypt(JSON.stringify(replacement)),
      },
      {
        type: 'removeSessionsForUser',
        keyPrefix: STORAGE_KEYS.SESSION_PREFIX,
        userId: address.userId,
      },
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
    const contactKey = this.getContactStorageKey(address, identityType);
    const existingValue = await this.storageBackend.getItem(contactKey);
    const existing = existingValue
      ? (JSON.parse(await this.decrypt(existingValue)) as ContactIdentityRecord)
      : null;
    if (!existing) throw new Error('Cannot verify an unseen identity');
    validateContactIdentityRecord(existing);
    const verified = verifyContactIdentityRecord(existing, identity, Date.now(), suppliedCommitment);
    await this.storageBackend.atomicWrite([
      { type: 'check', key: contactKey, expectedValue: existingValue },
      { type: 'set', key: contactKey, value: await this.encrypt(JSON.stringify(verified)) },
    ]);
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
      await this.readContactRecord(address, identityType),
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
    // Get existing prekeys and add/update the new one
    const allPrekeys = await this.getAllEcSignedPreKeys(identityType);
    const existingIndex = allPrekeys.findIndex((k) => k.keyId === signedPreKey.keyId);
    if (existingIndex >= 0) {
      allPrekeys[existingIndex] = signedPreKey;
    } else {
      allPrekeys.push(signedPreKey);
    }

    // Cleanup expired prekeys
    const cutoff = Date.now() - MAX_UNACKNOWLEDGED_SESSION_AGE_MS;
    const newest = allPrekeys.reduce((a, b) => (a.keyId > b.keyId ? a : b));
    const filtered = allPrekeys.filter(
      (k) => k.keyId === newest.keyId || (k.timestamp && k.timestamp > cutoff)
    );

    const encrypted = await this.encrypt(JSON.stringify(filtered));
    await this.storageBackend.setItem(this.getSignedPreKeyStorageKey(identityType), encrypted);
  }

  async getEcSignedPreKey(
    keyId?: number,
    identityType?: IdentityType
  ): Promise<EcSignedPreKey | null> {
    this.ensureInitialized();
    const allPrekeys = await this.getAllEcSignedPreKeys(identityType);
    if (allPrekeys.length === 0) return null;

    if (keyId !== undefined) {
      // Look up by specific keyId
      return allPrekeys.find((k) => k.keyId === keyId) ?? null;
    }

    // Return the most recent (highest keyId)
    return allPrekeys.reduce((latest, current) =>
      current.keyId > latest.keyId ? current : latest
    );
  }

  async getAllEcSignedPreKeys(identityType?: IdentityType): Promise<EcSignedPreKey[]> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getSignedPreKeyStorageKey(identityType)
    );
    if (!encrypted) {
      return [];
    }
    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async removeEcSignedPreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const allPrekeys = await this.getAllEcSignedPreKeys(identityType);
    const filtered = allPrekeys.filter((k) => k.keyId !== keyId);
    const encrypted = await this.encrypt(JSON.stringify(filtered));
    await this.storageBackend.setItem(this.getSignedPreKeyStorageKey(identityType), encrypted);
  }

  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const existing = await this.getEcOneTimePreKeys(identityType);
    await this.storageBackend.setItem(
      this.getEcOneTimePreKeyStorageKey(identityType),
      await this.encrypt(JSON.stringify([...existing, ...prekeys]))
    );
  }

  async getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getEcOneTimePreKeyStorageKey(identityType)
    );
    if (!encrypted) return [];

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const prekeys = await this.getEcOneTimePreKeys(identityType);
    const filtered = prekeys.filter((pk) => pk.keyId !== preKeyId);
    await this.storageBackend.setItem(
      this.getEcOneTimePreKeyStorageKey(identityType),
      await this.encrypt(JSON.stringify(filtered))
    );
  }

  async storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(kyberPreKey));
    await this.storageBackend.setItem(this.getKyberPreKeyStorageKey(identityType), encrypted);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getKyberPreKeyStorageKey(identityType)
    );
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
    // For simplicity, we'll store the usage record as metadata
    const usageKey = `${STORAGE_KEYS.PREKEY_PREFIX}kyber-usage:${identityType ?? 'aci'}:${kyberPreKeyId}`;
    const usage = {
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes: this.uint8ArrayToBase64(baseKeyBytes),
      usedAt: Date.now(),
    };
    await this.storageBackend.setItem(usageKey, JSON.stringify(usage));
  }

  // ============================================================================
  // KEM One-Time PreKey Management (Per-Session Post-Quantum Forward Secrecy)
  // ============================================================================
  // NOTE: This adapter is for bare React Native (non-Expo) apps.
  // Expo apps should still prefer ExpoSignalStore for the native SQLite backend.

  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    this.ensureInitialized();
    const existing = await this.getKemOneTimePreKeys(identityType);
    await this.storageBackend.setItem(
      this.getKemOneTimePreKeyStorageKey(identityType),
      await this.encrypt(JSON.stringify([...existing, ...prekeys]))
    );
  }

  async getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getKemOneTimePreKeyStorageKey(identityType)
    );
    if (!encrypted) return [];

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async getKemOneTimePreKey(
    keyId: number,
    identityType?: IdentityType
  ): Promise<KemOneTimePreKey | null> {
    const prekeys = await this.getKemOneTimePreKeys(identityType);
    return prekeys.find((prekey) => prekey.keyId === keyId) ?? null;
  }

  async removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    this.ensureInitialized();
    const prekeys = await this.getKemOneTimePreKeys(identityType);
    const filtered = prekeys.filter((prekey) => prekey.keyId !== keyId);
    await this.storageBackend.setItem(
      this.getKemOneTimePreKeyStorageKey(identityType),
      await this.encrypt(JSON.stringify(filtered))
    );
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
    const storageKey = `${STORAGE_KEYS.SESSION_PREFIX}${addressKey}`;
    const encrypted = await this.encrypt(serializeSessionRecord(record));

    const storedRecord: StoredSessionRecord = {
      userId: address.userId,
      deviceId: address.deviceId,
      data: encrypted,
      updatedAt: Date.now(),
    };

    await this.storageBackend.setItem(storageKey, JSON.stringify(storedRecord));
  }

  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    this.ensureInitialized();
    const addressKey = this.serializeAddress(address);
    const storageKey = `${STORAGE_KEYS.SESSION_PREFIX}${addressKey}`;
    const storedJson = await this.storageBackend.getItem(storageKey);
    if (!storedJson) return null;

    const stored = JSON.parse(storedJson) as StoredSessionRecord;
    const decrypted = await this.decrypt(stored.data);
    try {
      return deserializeSessionRecord(decrypted);
    } catch {
      await this.storageBackend.removeItem(storageKey);
      return null;
    }
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    this.ensureInitialized();
    assertCurrentSessionRecord(commit.record);
    const addressKey = this.serializeAddress(commit.address);
    const contactStorageKey = this.getContactStorageKey(
      commit.address,
      commit.contactIdentityType
    );
    const existingContactValue = await this.storageBackend.getItem(contactStorageKey);
    const existingContact = existingContactValue
      ? (JSON.parse(await this.decrypt(existingContactValue)) as ContactIdentityRecord)
      : null;
    if (existingContact) validateContactIdentityRecord(existingContact);
    const contactStatus = evaluateContactIdentityCandidate(
      existingContact,
      commit.contactIdentity
    );
    if (contactStatus !== 'NEW' && contactStatus !== 'MATCH') {
      throw new Error(`Atomic session/trust commit rejected contact identity status ${contactStatus}`);
    }
    const sessionStorageKey = `${STORAGE_KEYS.SESSION_PREFIX}${addressKey}`;
    const sessionValue = JSON.stringify({
      userId: commit.address.userId,
      deviceId: commit.address.deviceId,
      data: await this.encrypt(serializeSessionRecord(commit.record)),
      updatedAt: Date.now(),
    } satisfies StoredSessionRecord);

    const ecStorageKey = this.getEcOneTimePreKeyStorageKey(commit.localIdentityType);
    const kemStorageKey = this.getKemOneTimePreKeyStorageKey(commit.localIdentityType);
    const ecPrekeyValue =
      commit.oneTimePreKeyId === undefined
        ? null
        : await this.storageBackend.getItem(ecStorageKey);
    const kemPrekeyValue =
      commit.kemOneTimePreKeyId === undefined
        ? null
        : await this.storageBackend.getItem(kemStorageKey);
    const ecPrekeys = ecPrekeyValue
      ? (JSON.parse(await this.decrypt(ecPrekeyValue)) as EcOneTimePreKey[])
      : [];
    const kemPrekeys = kemPrekeyValue
      ? (JSON.parse(await this.decrypt(kemPrekeyValue)) as KemOneTimePreKey[])
      : [];
    if (
      commit.oneTimePreKeyId !== undefined &&
      !ecPrekeys.some((key) => key.keyId === commit.oneTimePreKeyId)
    ) {
      throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
    }
    if (
      commit.kemOneTimePreKeyId !== undefined &&
      !kemPrekeys.some((key) => key.keyId === commit.kemOneTimePreKeyId)
    ) {
      throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
    }
    const operations = [
      {
        type: 'check' as const,
        key: contactStorageKey,
        expectedValue: existingContactValue,
      },
      { type: 'set' as const, key: sessionStorageKey, value: sessionValue },
    ];
    if (contactStatus === 'NEW') {
      const newContact = createUnverifiedContactIdentityRecord(
        commit.contactIdentity,
        Date.now()
      );
      operations.push({
        type: 'set',
        key: contactStorageKey,
        value: await this.encrypt(JSON.stringify(newContact)),
      });
    }
    if (commit.oneTimePreKeyId !== undefined) {
      operations.push({ type: 'check', key: ecStorageKey, expectedValue: ecPrekeyValue });
      operations.push({
        type: 'set',
        key: ecStorageKey,
        value: await this.encrypt(
          JSON.stringify(ecPrekeys.filter((key) => key.keyId !== commit.oneTimePreKeyId))
        ),
      });
    }
    if (commit.kemOneTimePreKeyId !== undefined) {
      operations.push({ type: 'check', key: kemStorageKey, expectedValue: kemPrekeyValue });
      operations.push({
        type: 'set',
        key: kemStorageKey,
        value: await this.encrypt(
          JSON.stringify(kemPrekeys.filter((key) => key.keyId !== commit.kemOneTimePreKeyId))
        ),
      });
    }
    await this.storageBackend.atomicWrite(operations);
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    this.ensureInitialized();
    const addressKey = this.serializeAddress(address);
    const storageKey = `${STORAGE_KEYS.SESSION_PREFIX}${addressKey}`;
    await this.storageBackend.removeItem(storageKey);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    this.ensureInitialized();

    // With SessionRecord, archiving is handled at the DeviceRecord level
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
    // Get all keys with session prefix
    const allKeys = await this.storageBackend.getAllKeys();
    const sessionKeys = allKeys.filter((key) => key.startsWith(STORAGE_KEYS.SESSION_PREFIX));

    const sessions: SessionRecord[] = [];
    for (const key of sessionKeys) {
      const storedJson = await this.storageBackend.getItem(key);
      if (storedJson) {
        const stored = JSON.parse(storedJson) as StoredSessionRecord;
        if (stored.userId === userId) {
          const decrypted = await this.decrypt(stored.data);
          try {
            sessions.push(deserializeSessionRecord(decrypted));
          } catch {
            await this.storageBackend.removeItem(key);
          }
        }
      }
    }

    return sessions;
  }

  async hasSession(address: ProtocolAddress): Promise<boolean> {
    this.ensureInitialized();
    const record = await this.getSessionRecord(address);
    return record !== null && record.currentSession !== null;
  }

  // ============================================================================
  // Utility
  // ============================================================================

  async getSessionCount(): Promise<number> {
    this.ensureInitialized();

    // Get all session keys
    const allKeys = await this.storageBackend.getAllKeys();
    const sessionKeys = allKeys.filter((key) => key.startsWith(STORAGE_KEYS.SESSION_PREFIX));
    return sessionKeys.length;
  }

  async clearAllKeys(): Promise<void> {
    this.ensureInitialized();

    // Get all keys
    const allKeys = await this.storageBackend.getAllKeys();

    // Filter for signal keys
    const signalKeys = allKeys.filter((key) => key.startsWith('@signal:'));

    // Remove all signal keys
    await this.storageBackend.removeMany(signalKeys);
    this._metadata.clear();

    // Regenerate database key
    this.databaseKey = Crypto.getRandomBytes(32);
    await this.storageBackend.setItem(
      STORAGE_KEYS.DATABASE_KEY,
      this.uint8ArrayToBase64(this.databaseKey)
    );
  }

  // ============================================================================
  // Metadata storage
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    if (this._metadata.has(key)) {
      return this._metadata.get(key) ?? null;
    }

    const stored = await this.storageBackend.getItem(this.getMetadataStorageKey(key));
    if (stored === null) {
      return null;
    }

    this._metadata.set(key, stored);
    return stored;
  }

  async setMetadata(key: string, value: string): Promise<void> {
    this._metadata.set(key, value);
    await this.storageBackend.setItem(this.getMetadataStorageKey(key), value);
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Ensure the adapter is initialized
   * @throws Error if not initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized || !this.databaseKey) {
      throw new Error(
        'ReactNativeSignalStore was used before initialization completed. Create it with ReactNativeSignalStore.create(...).'
      );
    }
  }

  /**
   * Serialize ProtocolAddress to string key
   */
  private serializeAddress(address: ProtocolAddress): string {
    return `${address.userId}.${address.deviceId}`;
  }

  private getContactStorageKey(address: ProtocolAddress, identityType?: IdentityType): string {
    return `${STORAGE_KEYS.CONTACT_V1_PREFIX}${address.userId}:${identityType ?? 'aci'}`;
  }

  private async readContactRecord(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): Promise<ContactIdentityRecord | null> {
    const encrypted = await this.storageBackend.getItem(
      this.getContactStorageKey(address, identityType)
    );
    if (!encrypted) {
      // Alpha-format reset: delete the obsolete single-publicKey row.
      await this.storageBackend.removeItem(`${STORAGE_KEYS.CONTACT_PREFIX}${address.userId}`);
      return null;
    }
    const record = JSON.parse(await this.decrypt(encrypted)) as ContactIdentityRecord;
    validateContactIdentityRecord(record);
    return record;
  }

  private async writeContactRecord(
    storageKey: string,
    record: ContactIdentityRecord
  ): Promise<void> {
    validateContactIdentityRecord(record);
    await this.storageBackend.setItem(storageKey, await this.encrypt(JSON.stringify(record)));
  }

  /**
   * Encrypt data using AES-256-GCM
   *
   * Uses Signal Protocol crypto module with Web Crypto API.
   *
   * @param plaintext - Data to encrypt
   * @returns Base64-encoded: IV (12 bytes) + ciphertext + auth tag (16 bytes)
   */
  private async encrypt(plaintext: string): Promise<string> {
    if (!this.databaseKey) {
      throw new Error('Database key not available');
    }

    // Generate random IV (12 bytes for GCM)
    const iv = Crypto.getRandomBytes(12);

    // Encode plaintext
    const data = new TextEncoder().encode(plaintext);

    // Encrypt using proper AES-256-GCM via Signal Protocol crypto module
    const encrypted = await this.aesGcmEncrypt(data, this.databaseKey, iv);

    // Combine IV + ciphertext and encode as base64
    const combined = new Uint8Array(12 + encrypted.length);
    combined.set(iv, 0);
    combined.set(encrypted, 12);

    return this.uint8ArrayToBase64(combined);
  }

  /**
   * Decrypt data using AES-256-GCM
   *
   * @param encrypted - Base64-encoded: IV (12 bytes) + ciphertext + auth tag (16 bytes)
   * @returns Decrypted plaintext
   */
  private async decrypt(encrypted: string): Promise<string> {
    if (!this.databaseKey) {
      throw new Error('Database key not available');
    }

    // Decode from base64
    const combined = this.base64ToUint8Array(encrypted);

    // Extract IV and ciphertext
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    // Decrypt
    const plaintext = await this.aesGcmDecrypt(ciphertext, this.databaseKey, iv);

    // Decode plaintext
    return new TextDecoder().decode(plaintext);
  }

  /**
   * AES-256-GCM encryption using Web Crypto API
   *
   * Uses the Signal Protocol crypto module which provides proper AES-256-GCM.
   * Requires a Web Crypto API polyfill in bare React Native (e.g., react-native-quick-crypto).
   *
   * @param data - Plaintext to encrypt
   * @param key - 32-byte AES-256 key
   * @param iv - 12-byte initialization vector (already generated in encrypt())
   * @returns Ciphertext with appended 16-byte auth tag
   */
  private async aesGcmEncrypt(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    // Use the Signal crypto module's AES-GCM implementation
    const result = await SignalCrypto.aesGcmEncryptWithIV(key, data, iv);

    // Combine ciphertext + authTag into single buffer
    const ciphertextBytes = SignalCrypto.base64ToBytes(result.ciphertext);
    const authTagBytes = SignalCrypto.base64ToBytes(result.authTag);

    const combined = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
    combined.set(ciphertextBytes, 0);
    combined.set(authTagBytes, ciphertextBytes.length);

    return combined;
  }

  /**
   * AES-256-GCM decryption using Web Crypto API
   *
   * Uses the Signal Protocol crypto module which provides proper AES-256-GCM.
   * Requires a Web Crypto API polyfill in bare React Native (e.g., react-native-quick-crypto).
   *
   * @param ciphertext - Encrypted data with appended 16-byte auth tag
   * @param key - 32-byte AES-256 key
   * @param iv - 12-byte initialization vector
   * @returns Decrypted plaintext
   */
  private async aesGcmDecrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    // Validate minimum ciphertext length (must be at least 16 bytes for auth tag)
    const AES_GCM_TAG_BYTES = 16;
    if (ciphertext.length < AES_GCM_TAG_BYTES) {
      throw new Error(
        `Ciphertext too short: ${ciphertext.length} bytes (minimum ${AES_GCM_TAG_BYTES} for auth tag)`
      );
    }

    // Split ciphertext and auth tag (last 16 bytes)
    const ciphertextOnly = ciphertext.slice(0, -AES_GCM_TAG_BYTES);
    const authTag = ciphertext.slice(-AES_GCM_TAG_BYTES);

    // Use the Signal crypto module's AES-GCM implementation
    return await SignalCrypto.aesGcmDecrypt(
      key,
      SignalCrypto.bytesToBase64(ciphertextOnly),
      SignalCrypto.bytesToBase64(iv),
      SignalCrypto.bytesToBase64(authTag)
    );
  }

  /**
   * Log security event
   */
  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    const eventsJson = await this.storageBackend.getItem(STORAGE_KEYS.SECURITY_EVENTS);
    const events: SecurityEvent[] = eventsJson ? JSON.parse(eventsJson) : [];
    events.push(event);
    // Keep only last 100 events
    const trimmed = events.slice(-100);
    await this.storageBackend.setItem(STORAGE_KEYS.SECURITY_EVENTS, JSON.stringify(trimmed));
  }

  /**
   * Convert Uint8Array to base64
   */
  private uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return Buffer.from(binary, 'binary').toString('base64');
  }

  /**
   * Convert base64 to Uint8Array
   */
  private base64ToUint8Array(base64: string): Uint8Array {
    const binary = Buffer.from(base64, 'base64').toString('binary');
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private serializeUserRecord(record: UserRecord): SerializedUserRecord {
    return {
      ...record,
      devices: Array.from(record.devices.entries()),
    };
  }

  private deserializeUserRecord(data: SerializedUserRecord): UserRecord {
    return {
      ...data,
      devices: new Map(data.devices),
    };
  }

  private getIdentityKeyStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.IDENTITY_KEY_PREFIX}${identityType ?? 'aci'}`;
  }

  private getRegistrationIdStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.REGISTRATION_ID_PREFIX}${identityType ?? 'aci'}`;
  }

  private getMetadataStorageKey(key: string): string {
    return `${STORAGE_KEYS.METADATA_PREFIX}${key}`;
  }

  private getSignedPreKeyStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.PREKEY_PREFIX}signed-all:${identityType ?? 'aci'}`;
  }

  private getEcOneTimePreKeyStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.PREKEY_PREFIX}one-time:${identityType ?? 'aci'}`;
  }

  private getKyberPreKeyStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.PREKEY_PREFIX}kyber:${identityType ?? 'aci'}`;
  }

  private getKemOneTimePreKeyStorageKey(identityType?: IdentityType): string {
    return `${STORAGE_KEYS.PREKEY_PREFIX}kem-one-time:${identityType ?? 'aci'}`;
  }

  private getSesameUserStorageKey(userId: string): string {
    return `${STORAGE_KEYS.SESAME_USER_PREFIX}${userId}`;
  }

  private getSenderKeyRecordStorageKey(groupId: string, userId: string, deviceId: number): string {
    return `${STORAGE_KEYS.SENDER_KEY_RECORD_PREFIX}${groupId}:${userId}:${deviceId}`;
  }

  private getSkippedSenderKeyPrefix(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): string {
    return `${STORAGE_KEYS.SKIPPED_SENDER_KEY_PREFIX}${groupId}:${senderId}:${senderDeviceId}`;
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
    return `${STORAGE_KEYS.MESSAGE_RECORD_PREFIX}${sessionId}:${timestamp}`;
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(this.getSesameUserStorageKey(userId));
    if (!encrypted) {
      return null;
    }

    const decrypted = await this.decrypt(encrypted);
    return this.deserializeUserRecord(JSON.parse(decrypted));
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    this.ensureInitialized();
    const encrypted = await this.encrypt(JSON.stringify(this.serializeUserRecord(record)));
    await this.storageBackend.setItem(this.getSesameUserStorageKey(userId), encrypted);
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    const userRecord = await this.getUserRecord(userId);
    return userRecord?.devices.get(deviceId) ?? null;
  }

  async setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void> {
    let userRecord = await this.getUserRecord(userId);
    if (!userRecord) {
      userRecord = {
        userId,
        devices: new Map(),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    }

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

    if (userRecord.devices.size === 0) {
      await this.storageBackend.removeItem(this.getSesameUserStorageKey(userId));
      return;
    }

    await this.setUserRecord(userId, userRecord);
  }

  async deleteStaleRecords(maxLatency: number): Promise<number> {
    const now = Date.now();
    let deletedCount = 0;

    for (const userId of await this.getAllUserIds()) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      const devicesToDelete: number[] = [];
      for (const [deviceId, deviceRecord] of userRecord.devices) {
        const hasNoSessions =
          !deviceRecord.session ||
          (!deviceRecord.session.currentSession &&
            Object.keys(deviceRecord.session.archivedSessions).length === 0);
        const isStale = now - deviceRecord.updatedAt > maxLatency;

        if (hasNoSessions && isStale) {
          devicesToDelete.push(deviceId);
        }
      }

      for (const deviceId of devicesToDelete) {
        await this.deleteDeviceRecord(userId, deviceId);
        deletedCount++;
      }
    }

    return deletedCount;
  }

  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    const now = Date.now();
    let deletedCount = 0;

    for (const userId of await this.getAllUserIds()) {
      const userRecord = await this.getUserRecord(userId);
      if (!userRecord) continue;

      for (const [deviceId, deviceRecord] of userRecord.devices) {
        if (!deviceRecord.session) continue;

        let modified = false;
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

        const originalCount = Object.keys(deviceRecord.session.archivedSessions).length;
        const archivedKeys = Object.keys(deviceRecord.session.archivedSessions) as Base64[];
        for (const baseKey of archivedKeys) {
          const session = deviceRecord.session.archivedSessions[baseKey];
          if (session && now - session.createdAt > maxRecv) {
            delete deviceRecord.session.archivedSessions[baseKey];
          }
        }
        const removed = originalCount - Object.keys(deviceRecord.session.archivedSessions).length;
        if (removed > 0) {
          deletedCount += removed;
          modified = true;
        }

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
    const allKeys = await this.storageBackend.getAllKeys();
    return allKeys
      .filter((key) => key.startsWith(STORAGE_KEYS.SESAME_USER_PREFIX))
      .map((key) => key.slice(STORAGE_KEYS.SESAME_USER_PREFIX.length));
  }

  async getSesameDeviceIds(userId: string): Promise<number[]> {
    const userRecord = await this.getUserRecord(userId);
    return userRecord ? Array.from(userRecord.devices.keys()) : [];
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
    await this.storageBackend.removeItem(
      this.getSenderKeyRecordStorageKey(groupId, userId, deviceId)
    );
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const senderKeys = allKeys.filter((key) =>
      key.startsWith(`${STORAGE_KEYS.SENDER_KEY_RECORD_PREFIX}${groupId}:`)
    );

    const states: SenderKeyState[] = [];
    for (const key of senderKeys) {
      const encrypted = await this.storageBackend.getItem(key);
      if (!encrypted) continue;
      const decrypted = await this.decrypt(encrypted);
      const record = JSON.parse(decrypted) as SenderKeyState[];
      if (record[0]) {
        states.push(record[0]);
      }
    }

    return states;
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const senderKeys = allKeys.filter((key) =>
      key.startsWith(`${STORAGE_KEYS.SENDER_KEY_RECORD_PREFIX}${groupId}:`)
    );
    await this.storageBackend.removeMany(senderKeys);
    return senderKeys.length;
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

    await this.storageBackend.setItem(
      this.getSenderKeyRecordStorageKey(groupId, userId, deviceId),
      await this.encrypt(JSON.stringify(states))
    );
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getSenderKeyRecordStorageKey(groupId, userId, deviceId)
    );
    if (!encrypted) {
      return null;
    }

    const decrypted = await this.decrypt(encrypted);
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
    await this.storageBackend.setItem(
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex),
      await this.encrypt(JSON.stringify(messageKey))
    );
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex)
    );
    if (!encrypted) {
      return null;
    }

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    this.ensureInitialized();
    await this.storageBackend.removeItem(
      this.getSkippedSenderKeyStorageKey(groupId, senderId, senderDeviceId, chainIndex)
    );
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    return allKeys.filter((key) =>
      key.startsWith(this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId))
    ).length;
  }

  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const prefix = this.getSkippedSenderKeyPrefix(groupId, senderId, senderDeviceId);
    const matches = allKeys
      .filter((key) => key.startsWith(prefix))
      .map((key) => ({
        key,
        chainIndex: parseInt(key.split(':').pop() ?? '0', 10),
      }))
      .sort((a, b) => a.chainIndex - b.chainIndex)
      .slice(0, count);

    await this.storageBackend.removeMany(matches.map(({ key }) => key));
    return matches.length;
  }

  // ============================================================================
  // Message Record Storage (Not Yet Implemented)
  // Retry records are indexed by the client timestamp assigned before encryption.
  // ============================================================================

  async storeMessageRecord(record: MessageRecord): Promise<void> {
    this.ensureInitialized();
    await this.storageBackend.setItem(
      this.getMessageRecordStorageKey(record.sessionId, record.timestamp),
      await this.encrypt(JSON.stringify(record))
    );
  }

  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    this.ensureInitialized();
    const encrypted = await this.storageBackend.getItem(
      this.getMessageRecordStorageKey(sessionId, timestamp)
    );
    if (!encrypted) {
      return null;
    }

    const decrypted = await this.decrypt(encrypted);
    return JSON.parse(decrypted);
  }

  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    this.ensureInitialized();
    await this.storageBackend.removeItem(this.getMessageRecordStorageKey(sessionId, timestamp));
  }

  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    this.ensureInitialized();
    const cutoff = Date.now() - maxAgeMs;
    const allKeys = await this.storageBackend.getAllKeys();
    const messageKeys = allKeys.filter((key) => key.startsWith(STORAGE_KEYS.MESSAGE_RECORD_PREFIX));

    const toDelete: string[] = [];
    for (const key of messageKeys) {
      const encrypted = await this.storageBackend.getItem(key);
      if (!encrypted) continue;
      const decrypted = await this.decrypt(encrypted);
      const record = JSON.parse(decrypted) as MessageRecord;
      if (record.createdAt < cutoff) {
        toDelete.push(key);
      }
    }

    if (toDelete.length > 0) {
      await this.storageBackend.removeMany(toDelete);
    }
    return toDelete.length;
  }

  async clearAllMessageRecords(): Promise<number> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const messageKeys = allKeys.filter((key) => key.startsWith(STORAGE_KEYS.MESSAGE_RECORD_PREFIX));
    if (messageKeys.length > 0) {
      await this.storageBackend.removeMany(messageKeys);
    }
    return messageKeys.length;
  }

  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const messageKeys = allKeys.filter((key) =>
      key.startsWith(`${STORAGE_KEYS.MESSAGE_RECORD_PREFIX}${sessionId}:`)
    );
    if (messageKeys.length > 0) {
      await this.storageBackend.removeMany(messageKeys);
    }
    return messageKeys.length;
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
    const signedPreKeys = await this.getAllEcSignedPreKeys(identityType);
    const ecOneTimePreKeys = await this.getEcOneTimePreKeys(identityType);
    const kyberPreKey = await this.getKyberPreKey(identityType);
    const kemOneTimePreKeys = await this.getKemOneTimePreKeys(identityType);
    const it = identityType ?? 'aci';

    await this.storageBackend.removeMany([
      this.getSignedPreKeyStorageKey(identityType),
      this.getEcOneTimePreKeyStorageKey(identityType),
      this.getKyberPreKeyStorageKey(identityType),
      this.getKemOneTimePreKeyStorageKey(identityType),
    ]);

    const allKeys = await this.storageBackend.getAllKeys();
    const kyberUsageKeys = allKeys.filter((key) =>
      key.startsWith(`${STORAGE_KEYS.PREKEY_PREFIX}kyber-usage:${it}:`)
    );
    if (kyberUsageKeys.length > 0) {
      await this.storageBackend.removeMany(kyberUsageKeys);
    }

    return {
      ecSignedPreKeys: signedPreKeys.length,
      ecOneTimePreKeys: ecOneTimePreKeys.length,
      kyberPreKeys: kyberPreKey ? 1 : 0,
      kemOneTimePreKeys: kemOneTimePreKeys.length,
    };
  }

  async clearAllSessions(): Promise<void> {
    this.ensureInitialized();
    const allKeys = await this.storageBackend.getAllKeys();
    const sessionKeys = allKeys.filter(
      (key) =>
        key.startsWith(STORAGE_KEYS.SESSION_PREFIX) ||
        key.startsWith(STORAGE_KEYS.SESAME_USER_PREFIX)
    );
    if (sessionKeys.length > 0) {
      await this.storageBackend.removeMany(sessionKeys);
    }
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
    const allKeys = await this.storageBackend.getAllKeys();
    return {
      sessions: allKeys.filter((key) => key.startsWith(STORAGE_KEYS.SESSION_PREFIX)).length,
      ecSignedPreKeys:
        (await this.getAllEcSignedPreKeys('aci')).length +
        (await this.getAllEcSignedPreKeys('pni')).length,
      ecOneTimePreKeys:
        (await this.getEcOneTimePreKeys('aci')).length +
        (await this.getEcOneTimePreKeys('pni')).length,
      kyberPreKeys:
        ((await this.getKyberPreKey('aci')) ? 1 : 0) + ((await this.getKyberPreKey('pni')) ? 1 : 0),
      kemOneTimePreKeys:
        (await this.getKemOneTimePreKeys('aci')).length +
        (await this.getKemOneTimePreKeys('pni')).length,
      users: allKeys.filter((key) => key.startsWith(STORAGE_KEYS.SESAME_USER_PREFIX)).length,
    };
  }
}
