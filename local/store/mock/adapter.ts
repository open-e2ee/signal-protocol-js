/**
 * Mock Storage Adapter
 *
 * In-memory storage adapter for local development.
 * Uses Map/Set for fast storage without any external dependencies.
 *
 * WARNING: All data is lost when the adapter is destroyed.
 * DO NOT use in production.
 */

import type {
  ISignalLocalStore,
  MessageRecord,
  SkippedSenderMessageKey,
  SessionTrustCommit,
} from '../../../types';
import {
  assertCurrentSessionRecord,
  CURRENT_SESSION_RECORD_VERSION,
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
  verifyContactIdentityRecord,
  validateContactIdentityRecord,
} from '../../../keys/identity';
import type { SessionState } from '../../../types';
import type { ProtocolAddress } from '../../../types/address';
import { IdentityKeyChange, TrustDirection } from '../../../types/trust';
import type { UserRecord, DeviceRecord } from '../../../types';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import { generateRandomBytes } from '../../../internal/crypto/random';
import { base64ToBytes } from '../../../internal/crypto/utils';

/**
 * Mock storage adapter for local development
 *
 * Provides in-memory storage with the same interface as production adapters.
 * Useful when persistent storage is intentionally unnecessary.
 *
 * @example
 * ```typescript
 * const storage = new MockSignalStore();
 *
 * // Use like any other storage adapter
 * await storage.storeIdentityKey(keyPair);
 * const retrieved = await storage.getIdentityKey();
 * ```
 */
export {};
export class MockSignalStore implements ISignalLocalStore {
  // Identity keys and registration IDs keyed by identityType
  private identityKeys = new Map<IdentityType, IdentityKeyPair>();
  private registrationIds = new Map<IdentityType, number>();
  private contactIdentities = new Map<string, ContactIdentityRecord>();
  /** Map of "identityType:keyId" -> EcSignedPreKey (supports looking up old prekeys) */
  private ecSignedPreKeys = new Map<string, EcSignedPreKey>();
  /** Map of "identityType:keyId" -> EcOneTimePreKey */
  private ecOneTimePreKeys = new Map<string, EcOneTimePreKey>();
  /** Map of identityType -> KyberPreKey */
  private kyberPreKeys = new Map<IdentityType, KyberPreKey>();
  /** Map of "identityType:keyId" -> KemOneTimePreKey */
  private kemOneTimePreKeys = new Map<string, KemOneTimePreKey>();
  private kyberUsage = new Map<string, { signedPreKeyId: number; baseKeyBytes: Uint8Array }>();
  private sessionRecords = new Map<string, SessionRecord>();
  private databaseKey: Uint8Array | null = null;

  // SESAME multi-device session management
  private sesameUserRecords = new Map<string, UserRecord>();

  // Sender Keys for group messaging (groupId -> userId -> deviceId -> SenderKeyState)
  private senderKeys = new Map<string, Map<string, Map<number, SenderKeyState>>>();

  // Sender Key Records: full state arrays (current + previous) keyed by "groupId:userId:deviceId"
  private senderKeyRecords = new Map<string, SenderKeyState[]>();

  // Skipped sender keys for out-of-order messages (composite key -> messageKey)
  // Signal uses capacity-only limits (no time-based expiration)
  private skippedSenderKeys = new Map<string, SkippedSenderMessageKey>();

  // Message records for SESAME retry request support
  // Key format: "sessionId:timestamp" for primary lookup
  // Also indexed by timestamp for delivery receipt processing
  private messageRecords = new Map<string, MessageRecord>();

  // Metadata storage
  private readonly _metadata = new Map<string, string>();

  // ============================================================================
  // Identity Key Management (Own Keys)
  // ============================================================================

  async storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.identityKeys.set(it, keyPair);
  }

  async getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null> {
    const it = identityType ?? 'aci';
    return this.identityKeys.get(it) ?? null;
  }

  async hasIdentityKey(identityType?: IdentityType): Promise<boolean> {
    const it = identityType ?? 'aci';
    return this.identityKeys.has(it);
  }

  async getLocalRegistrationId(identityType?: IdentityType): Promise<number> {
    const it = identityType ?? 'aci';
    return this.registrationIds.get(it) ?? 0;
  }

  async setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.registrationIds.set(it, id);
  }

  // ============================================================================
  // Identity Verification (Contact Identity Keys)
  // ============================================================================

  async saveContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<IdentityKeyChange> {
    const key = this.getContactIdentityKey(address, identityType);
    const existing = this.contactIdentities.get(key) ?? null;
    const status = evaluateContactIdentityCandidate(existing, identity, suppliedCommitment);
    if (status === 'NEW') {
      this.contactIdentities.set(key, createUnverifiedContactIdentityRecord(identity, Date.now()));
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
    const record = this.contactIdentities.get(this.getContactIdentityKey(address, identityType));
    if (!record) return null;
    validateContactIdentityRecord(record);
    return structuredClone(record);
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
    const key = this.getContactIdentityKey(address, identityType);
    const existing = this.contactIdentities.get(key);
    if (!existing) throw new Error('Cannot rotate an unseen identity');
    const replacement = acceptRotation(existing, identity, Date.now(), suppliedCommitment);

    // Validate and stage every effect before mutating any live map.
    const sessionKeys = [...this.sessionRecords.entries()]
      .filter(([, record]) => {
        const states = [record.currentSession, ...Object.values(record.archivedSessions)];
        return states.some((state) => state?.remoteAddress?.userId === address.userId);
      })
      .map(([sessionKey]) => sessionKey);

    this.contactIdentities.set(key, replacement);
    for (const sessionKey of sessionKeys) this.sessionRecords.delete(sessionKey);
    return structuredClone(replacement);
  }

  async verifyContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    const key = this.getContactIdentityKey(address, identityType);
    const existing = this.contactIdentities.get(key);
    if (!existing) throw new Error('Cannot verify an unseen identity');
    const verified = verifyContactIdentityRecord(
      existing,
      identity,
      Date.now(),
      suppliedCommitment
    );
    this.contactIdentities.set(key, verified);
    return structuredClone(verified);
  }

  async isTrustedIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    _direction: TrustDirection,
    identityType?: IdentityType
  ): Promise<boolean> {
    const saved = this.contactIdentities.get(this.getContactIdentityKey(address, identityType));
    return evaluateContactIdentityCandidate(saved ?? null, identity) !== 'CHANGED' &&
      evaluateContactIdentityCandidate(saved ?? null, identity) !== 'ROLLBACK';
  }

  // ============================================================================
  // PreKey Management
  // ============================================================================

  async storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    // Store by identityType:keyId (supports multiple prekeys for grace period handling)
    this.ecSignedPreKeys.set(`${it}:${signedPreKey.keyId}`, signedPreKey);
  }

  async getEcSignedPreKey(
    keyId?: number,
    identityType?: IdentityType
  ): Promise<EcSignedPreKey | null> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;

    if (keyId !== undefined) {
      // Look up by specific keyId
      return this.ecSignedPreKeys.get(`${prefix}${keyId}`) ?? null;
    }
    // Return the most recent EC signed prekey (highest keyId) for this identityType
    let maxKeyId = -1;
    let result: EcSignedPreKey | null = null;
    for (const [key, value] of this.ecSignedPreKeys.entries()) {
      if (key.startsWith(prefix)) {
        const id = parseInt(key.slice(prefix.length), 10);
        if (id > maxKeyId) {
          maxKeyId = id;
          result = value;
        }
      }
    }
    return result;
  }

  async getAllEcSignedPreKeys(identityType?: IdentityType): Promise<EcSignedPreKey[]> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;
    const result: EcSignedPreKey[] = [];
    for (const [key, value] of this.ecSignedPreKeys.entries()) {
      if (key.startsWith(prefix)) {
        result.push(value);
      }
    }
    return result;
  }

  async removeEcSignedPreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.ecSignedPreKeys.delete(`${it}:${keyId}`);
  }

  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    for (const pk of prekeys) {
      this.ecOneTimePreKeys.set(`${it}:${pk.keyId}`, pk);
    }
  }

  async getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;
    const result: EcOneTimePreKey[] = [];
    for (const [key, value] of this.ecOneTimePreKeys.entries()) {
      if (key.startsWith(prefix)) {
        result.push(value);
      }
    }
    return result;
  }

  async removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.ecOneTimePreKeys.delete(`${it}:${preKeyId}`);
  }

  async storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.kyberPreKeys.set(it, kyberPreKey);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    const it = identityType ?? 'aci';
    return this.kyberPreKeys.get(it) ?? null;
  }

  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    this.kyberUsage.set(`${it}:${kyberPreKeyId}`, { signedPreKeyId, baseKeyBytes });
  }

  // ============================================================================
  // KEM One-Time PreKey Management (Per-Session Post-Quantum Forward Secrecy)
  // ============================================================================

  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    for (const pk of prekeys) {
      this.kemOneTimePreKeys.set(`${it}:${pk.keyId}`, pk);
    }
  }

  async getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;
    const result: KemOneTimePreKey[] = [];
    for (const [key, value] of this.kemOneTimePreKeys.entries()) {
      if (key.startsWith(prefix)) {
        result.push(value);
      }
    }
    return result;
  }

  async getKemOneTimePreKey(
    keyId: number,
    identityType?: IdentityType
  ): Promise<KemOneTimePreKey | null> {
    const it = identityType ?? 'aci';
    return this.kemOneTimePreKeys.get(`${it}:${keyId}`) ?? null;
  }

  async removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    this.kemOneTimePreKeys.delete(`${it}:${keyId}`);
  }

  async getKemOneTimePreKeyCount(identityType?: IdentityType): Promise<number> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;
    let count = 0;
    for (const key of this.kemOneTimePreKeys.keys()) {
      if (key.startsWith(prefix)) {
        count++;
      }
    }
    return count;
  }

  // ============================================================================
  // Session Management
  // ============================================================================

  /**
   * Store session record
   */
  async storeSessionRecord(address: ProtocolAddress, record: SessionRecord): Promise<void> {
    assertCurrentSessionRecord(record);
    const key = this.getAddressKey(address);
    this.sessionRecords.set(key, record);
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    assertCurrentSessionRecord(commit.record);
    const sessionKey = this.getAddressKey(commit.address);
    const contactKey = this.getContactIdentityKey(
      commit.address,
      commit.contactIdentityType
    );
    const existingContact = this.contactIdentities.get(contactKey) ?? null;
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
    const ecKey =
      commit.oneTimePreKeyId === undefined
        ? undefined
        : `${commit.localIdentityType}:${commit.oneTimePreKeyId}`;
    const kemKey =
      commit.kemOneTimePreKeyId === undefined
        ? undefined
        : `${commit.localIdentityType}:${commit.kemOneTimePreKeyId}`;
    if (ecKey && !this.ecOneTimePreKeys.has(ecKey)) {
      throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
    }
    if (kemKey && !this.kemOneTimePreKeys.has(kemKey)) {
      throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
    }

    // Map mutations cannot fail after validation; this is one synchronous commit point.
    if (newContact) this.contactIdentities.set(contactKey, newContact);
    this.sessionRecords.set(sessionKey, commit.record);
    if (ecKey) this.ecOneTimePreKeys.delete(ecKey);
    if (kemKey) this.kemOneTimePreKeys.delete(kemKey);
  }

  /**
   * Get session record
   * Returns SessionRecord format for ISignalLocalStore interface compatibility
   */
  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    const key = this.getAddressKey(address);
    const record = this.sessionRecords.get(key);
    if (!record) return null;
    try {
      assertCurrentSessionRecord(record);
      return record;
    } catch {
      this.sessionRecords.delete(key);
      return null;
    }
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    const key = this.getAddressKey(address);
    this.sessionRecords.delete(key);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    // Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"
    // This preserves the old session for potential delayed message decryption
    const key = this.getAddressKey(address);
    const record = this.sessionRecords.get(key);

    if (record && record.currentSession) {
      // Archive the current session before replacing
      if (!record.archivedSessions) {
        record.archivedSessions = {};
      }
      record.archivedSessions[record.currentSession.baseKey] = record.currentSession;
    }

    if (record) {
      // Set new current session (may be null/undefined to clear)
      record.currentSession = newSession ?? null;
      if (record.metadata) record.metadata.lastSentAt = Date.now();
      this.sessionRecords.set(key, record);
    } else if (newSession) {
      // Create new record with just the new session
      this.sessionRecords.set(key, {
        currentSession: newSession,
        archivedSessions: {},
        version: CURRENT_SESSION_RECORD_VERSION,
      });
    }
  }

  async getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    const sessions: SessionRecord[] = [];

    for (const [key, record] of this.sessionRecords.entries()) {
      // Check if key starts with userId (format: "userId.deviceId")
      if (key.startsWith(`${userId}.`) || key === userId) {
        try {
          assertCurrentSessionRecord(record);
          sessions.push(record);
        } catch {
          this.sessionRecords.delete(key);
        }
      }
    }

    return sessions;
  }

  async hasSession(address: ProtocolAddress): Promise<boolean> {
    const key = this.getAddressKey(address);
    return this.sessionRecords.has(key);
  }

  async getSessionCount(): Promise<number> {
    return this.sessionRecords.size;
  }

  // ============================================================================
  // Database Encryption
  // ============================================================================

  async getDatabaseKey(): Promise<Uint8Array> {
    if (!this.databaseKey) {
      this.databaseKey = await generateRandomBytes(32);
    }
    return this.databaseKey;
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    return this.sesameUserRecords.get(userId) ?? null;
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    this.sesameUserRecords.set(userId, record);
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    // Try live session record first for up-to-date state (SPQR epochs, DH ratchet keys)
    // This mirrors ExpoKeyStorageAdapter.getDeviceRecord which builds from getSessionRecord()
    const address = { userId, deviceId };
    const sessionRecord = await this.getSessionRecord(address);

    if (sessionRecord) {
      const now = Date.now();
      return {
        userId,
        deviceId,
        // Generic SESAME session records are permitted to omit this SDK's
        // composite profile. DeviceRecord identity bytes never mutate the
        // account-scoped composite trust store.
        identityKey: sessionRecord.currentSession?.remoteIdentity
          ? base64ToBytes(sessionRecord.currentSession.remoteIdentity.x25519PublicKey)
          : new Uint8Array(),
        session: sessionRecord,
        createdAt: sessionRecord.metadata?.createdAt ?? now,
        updatedAt: now,
      };
    }

    // Fall back to sesameUserRecords for device records without active sessions
    const userRecord = this.sesameUserRecords.get(userId);
    if (!userRecord) return null;
    return userRecord.devices.get(deviceId) ?? null;
  }

  async setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void> {
    const address = { userId, deviceId };

    // Store session directly to sessionRecords (preserving exact data including metadata state)
    // We write directly instead of through storeSessionRecord() to avoid metadata auto-generation
    if (record.session) {
      const key = this.getAddressKey(address);
      this.sessionRecords.set(key, record.session);
    }

    // Also keep sesameUserRecords in sync for getUserRecord()
    let userRecord = this.sesameUserRecords.get(userId);
    if (!userRecord) {
      userRecord = {
        userId,
        devices: new Map(),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      this.sesameUserRecords.set(userId, userRecord);
    }
    userRecord.devices.set(deviceId, record);
    userRecord.updatedAt = Date.now();
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    // Delete session via canonical path (mirrors ExpoKeyStorageAdapter.deleteDeviceRecord)
    const address = { userId, deviceId };
    await this.deleteSessionRecord(address);

    // Also clean up sesameUserRecords
    const userRecord = this.sesameUserRecords.get(userId);
    if (!userRecord) return;

    userRecord.devices.delete(deviceId);
    userRecord.updatedAt = Date.now();

    if (userRecord.devices.size === 0) {
      this.sesameUserRecords.delete(userId);
    }
  }

  // New session methods (use DeviceRecord.session directly)
  async getDeviceSession(userId: string, deviceId: number): Promise<SessionRecord | null> {
    const deviceRecord = await this.getDeviceRecord(userId, deviceId);
    return deviceRecord?.session ?? null;
  }

  async setDeviceSession(userId: string, deviceId: number, session: SessionRecord): Promise<void> {
    const deviceRecord = await this.getDeviceRecord(userId, deviceId);
    if (!deviceRecord) {
      throw new Error(`Device record not found: ${userId}:${deviceId}`);
    }

    deviceRecord.session = session;
    deviceRecord.updatedAt = Date.now();

    await this.setDeviceRecord(userId, deviceId, deviceRecord);
  }

  async deleteStaleRecords(maxLatency: number): Promise<number> {
    let deleted = 0;
    const now = Date.now();

    for (const [userId, userRecord] of this.sesameUserRecords.entries()) {
      const devicesToDelete: number[] = [];

      for (const [deviceId, deviceRecord] of userRecord.devices.entries()) {
        // A record is stale if:
        // 1. It has no session (or session has no currentSession and no archived)
        // 2. It's older than maxLatency
        const hasNoSessions =
          !deviceRecord.session ||
          (!deviceRecord.session.currentSession &&
            Object.keys(deviceRecord.session.archivedSessions).length === 0);

        const isOld = now - deviceRecord.createdAt > maxLatency;

        if (hasNoSessions && isOld) {
          devicesToDelete.push(deviceId);
        }
      }

      for (const deviceId of devicesToDelete) {
        userRecord.devices.delete(deviceId);
        deleted++;
      }

      userRecord.updatedAt = Date.now();

      // Clean up empty user records
      if (userRecord.devices.size === 0) {
        this.sesameUserRecords.delete(userId);
      }
    }

    return deleted;
  }

  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    let deleted = 0;
    const now = Date.now();

    for (const userRecord of this.sesameUserRecords.values()) {
      for (const deviceRecord of userRecord.devices.values()) {
        if (!deviceRecord.session) continue;

        const sessionRecord = deviceRecord.session;
        const createdAt = sessionRecord.metadata?.createdAt ?? 0;
        const age = now - createdAt;

        // Check if session is expired
        if (age > maxRecv) {
          // Count all sessions being deleted: 1 for current + all archived
          if (sessionRecord.currentSession) {
            deleted++;
          }
          deleted += Object.keys(sessionRecord.archivedSessions).length;

          // Clear the session from both storage maps
          deviceRecord.session = null;
          const key = `${deviceRecord.userId}.${deviceRecord.deviceId}`;
          this.sessionRecords.delete(key);
        } else {
          // Check archived sessions for expiration individually
          const expiredKeys: string[] = [];
          for (const [baseKey, sessionState] of Object.entries(sessionRecord.archivedSessions)) {
            // Check if this individual session is expired based on its lastUsedAt
            const sessionLastUsed = sessionState?.lastUsedAt ?? createdAt;
            const sessionAge = now - sessionLastUsed;
            if (sessionAge > maxRecv) {
              expiredKeys.push(baseKey);
              deleted++;
            }
          }

          // Remove expired archived sessions
          for (const key of expiredKeys) {
            delete sessionRecord.archivedSessions[
              key as keyof typeof sessionRecord.archivedSessions
            ];
          }
        }

        deviceRecord.updatedAt = Date.now();
      }

      userRecord.updatedAt = Date.now();
    }

    return deleted;
  }

  async getAllUserIds(): Promise<string[]> {
    return Array.from(this.sesameUserRecords.keys());
  }

  async getSesameDeviceIds(userId: string): Promise<number[]> {
    const userRecord = this.sesameUserRecords.get(userId);
    if (!userRecord) return [];

    return Array.from(userRecord.devices.keys());
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
    if (!this.senderKeys.has(groupId)) {
      this.senderKeys.set(groupId, new Map());
    }
    const groupMap = this.senderKeys.get(groupId)!;

    if (!groupMap.has(userId)) {
      groupMap.set(userId, new Map());
    }
    const userMap = groupMap.get(userId)!;

    userMap.set(deviceId, state);
  }

  async getSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null> {
    const groupMap = this.senderKeys.get(groupId);
    if (!groupMap) return null;

    const userMap = groupMap.get(userId);
    if (!userMap) return null;

    return userMap.get(deviceId) ?? null;
  }

  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    const groupMap = this.senderKeys.get(groupId);
    if (!groupMap) return;

    const userMap = groupMap.get(userId);
    if (!userMap) return;

    userMap.delete(deviceId);

    // Clean up corresponding sender key record
    this.senderKeyRecords.delete(this.getSenderKeyRecordKey(groupId, userId, deviceId));

    // Clean up empty maps
    if (userMap.size === 0) {
      groupMap.delete(userId);
    }
    if (groupMap.size === 0) {
      this.senderKeys.delete(groupId);
    }
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    const groupMap = this.senderKeys.get(groupId);
    if (!groupMap) return [];

    const allKeys: SenderKeyState[] = [];
    for (const userMap of groupMap.values()) {
      for (const state of userMap.values()) {
        allKeys.push(state);
      }
    }

    return allKeys;
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    const groupMap = this.senderKeys.get(groupId);
    if (!groupMap) return 0;

    let count = 0;
    for (const [userId, userMap] of groupMap.entries()) {
      for (const deviceId of userMap.keys()) {
        this.senderKeyRecords.delete(this.getSenderKeyRecordKey(groupId, userId, deviceId));
      }
      count += userMap.size;
    }

    this.senderKeys.delete(groupId);
    return count;
  }

  // ============================================================================
  // Sender Key Records (Current + Previous States)
  // ============================================================================

  private getSenderKeyRecordKey(groupId: string, userId: string, deviceId: number): string {
    return `${groupId}:${userId}:${deviceId}`;
  }

  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void> {
    if (states.length === 0) return;

    // Store current state via existing storeSenderKey
    await this.storeSenderKey(groupId, userId, deviceId, states[0]);

    // Store the full record
    const key = this.getSenderKeyRecordKey(groupId, userId, deviceId);
    this.senderKeyRecords.set(key, [...states]);
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    const key = this.getSenderKeyRecordKey(groupId, userId, deviceId);
    const record = this.senderKeyRecords.get(key);
    if (record) return [...record];

    // Fall back to current state only
    const currentState = await this.getSenderKey(groupId, userId, deviceId);
    if (!currentState) return null;
    return [currentState];
  }

  // ============================================================================
  // Skipped Sender Keys (Out-of-Order Message Support - Spec Section 4.1)
  // ============================================================================

  private getSkippedKeyId(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): string {
    return `${groupId}:${senderId}:${senderDeviceId}:${chainIndex}`;
  }

  async storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void> {
    const key = this.getSkippedKeyId(groupId, senderId, senderDeviceId, chainIndex);
    this.skippedSenderKeys.set(key, messageKey);
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null> {
    const key = this.getSkippedKeyId(groupId, senderId, senderDeviceId, chainIndex);
    return this.skippedSenderKeys.get(key) ?? null;
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    const key = this.getSkippedKeyId(groupId, senderId, senderDeviceId, chainIndex);
    this.skippedSenderKeys.delete(key);
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    const prefix = `${groupId}:${senderId}:${senderDeviceId}:`;
    let count = 0;

    for (const key of this.skippedSenderKeys.keys()) {
      if (key.startsWith(prefix)) {
        count++;
      }
    }

    return count;
  }

  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    const prefix = `${groupId}:${senderId}:${senderDeviceId}:`;

    // Collect all keys for this sender with their chain indices
    const keysWithIndices: { key: string; chainIndex: number }[] = [];

    for (const key of this.skippedSenderKeys.keys()) {
      if (key.startsWith(prefix)) {
        // Extract chain index from key (last part after the last colon)
        const chainIndex = parseInt(key.split(':').pop()!, 10);
        keysWithIndices.push({ key, chainIndex });
      }
    }

    // Sort by chain index (ascending = oldest first)
    keysWithIndices.sort((a, b) => a.chainIndex - b.chainIndex);

    // Delete the oldest ones
    const toDelete = keysWithIndices.slice(0, count);
    for (const { key } of toDelete) {
      this.skippedSenderKeys.delete(key);
    }

    return toDelete.length;
  }

  // ============================================================================
  // Message Record Storage (SESAME Retry Request Support)
  // Retry records are indexed by the client timestamp assigned before encryption.
  // ============================================================================

  private getMessageRecordKey(sessionId: string, timestamp: number): string {
    return `${sessionId}:${timestamp}`;
  }

  async storeMessageRecord(record: MessageRecord): Promise<void> {
    const key = this.getMessageRecordKey(record.sessionId, record.timestamp);
    this.messageRecords.set(key, { ...record });
  }

  /**
   * Get a message record by session and timestamp (PRIMARY method).
   * Per Signal Protocol, messages are identified by client timestamp.
   */
  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    const key = this.getMessageRecordKey(sessionId, timestamp);
    const record = this.messageRecords.get(key);
    return record ? { ...record } : null;
  }

  /**
   * Delete a message record by session and timestamp (PRIMARY method).
   */
  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    const key = this.getMessageRecordKey(sessionId, timestamp);
    this.messageRecords.delete(key);
  }

  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    const cutoff = Date.now() - maxAgeMs;
    let deleted = 0;

    for (const [key, record] of this.messageRecords.entries()) {
      if (record.createdAt < cutoff) {
        this.messageRecords.delete(key);
        deleted++;
      }
    }

    return deleted;
  }

  async clearAllMessageRecords(): Promise<number> {
    const count = this.messageRecords.size;
    this.messageRecords.clear();
    return count;
  }

  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    let deleted = 0;

    for (const [key, record] of this.messageRecords.entries()) {
      if (record.sessionId === sessionId) {
        this.messageRecords.delete(key);
        deleted++;
      }
    }

    return deleted;
  }

  // ============================================================================
  // Utility
  // ============================================================================

  async clearAllKeys(): Promise<void> {
    this.identityKeys.clear();
    this.registrationIds.clear();
    this.contactIdentities.clear();
    this.ecSignedPreKeys.clear();
    this.ecOneTimePreKeys.clear();
    this.kyberPreKeys.clear();
    this.kemOneTimePreKeys.clear();
    this.kyberUsage.clear();
    this.sessionRecords.clear();
    this.databaseKey = null;
    this.sesameUserRecords.clear();
    this.senderKeys.clear();
    this.senderKeyRecords.clear();
    this.skippedSenderKeys.clear();
    this.messageRecords.clear();
    this._metadata.clear();
  }

  // ============================================================================
  // Metadata storage
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    return this._metadata.get(key) ?? null;
  }

  async setMetadata(key: string, value: string): Promise<void> {
    this._metadata.set(key, value);
  }

  // ============================================================================
  // Key Recovery Methods (Bug #7 - Identifier Collision Recovery)
  // ============================================================================

  /**
   * Get the maximum EC signed prekey ID in storage.
   * Used to generate new keyIds that won't collide with existing ones.
   *
   * @returns The highest EC signed prekey ID, or 0 if none exist
   */
  async getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;
    let maxId = 0;
    for (const key of this.ecSignedPreKeys.keys()) {
      if (key.startsWith(prefix)) {
        const id = parseInt(key.slice(prefix.length), 10);
        if (id > maxId) maxId = id;
      }
    }
    return maxId;
  }

  /**
   * Get the maximum Kyber prekey ID in storage.
   * Used to generate new keyIds that won't collide with existing ones.
   *
   * @returns The highest Kyber prekey ID, or 0 if none exist
   */
  async getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    const it = identityType ?? 'aci';
    const kyberPreKey = this.kyberPreKeys.get(it);
    if (!kyberPreKey) {
      return 0;
    }
    return kyberPreKey.keyId;
  }

  /**
   * Delete all prekeys from storage (preserves identity keys and sessions).
   * Used for recovery from identifier collision per PQXDH §4.13.
   *
   * @returns Counts of deleted prekeys by type
   */
  async deleteAllPreKeys(identityType?: IdentityType): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }> {
    const it = identityType ?? 'aci';
    const prefix = `${it}:`;

    let ecSignedPreKeysCount = 0;
    for (const key of this.ecSignedPreKeys.keys()) {
      if (key.startsWith(prefix)) {
        this.ecSignedPreKeys.delete(key);
        ecSignedPreKeysCount++;
      }
    }

    let ecOneTimePreKeysCount = 0;
    for (const key of this.ecOneTimePreKeys.keys()) {
      if (key.startsWith(prefix)) {
        this.ecOneTimePreKeys.delete(key);
        ecOneTimePreKeysCount++;
      }
    }

    const kyberPreKeysCount = this.kyberPreKeys.has(it) ? 1 : 0;
    this.kyberPreKeys.delete(it);

    let kemOneTimePreKeysCount = 0;
    for (const key of this.kemOneTimePreKeys.keys()) {
      if (key.startsWith(prefix)) {
        this.kemOneTimePreKeys.delete(key);
        kemOneTimePreKeysCount++;
      }
    }

    // Clean up kyber usage entries for this identity type
    for (const key of this.kyberUsage.keys()) {
      if (key.startsWith(prefix)) {
        this.kyberUsage.delete(key);
      }
    }

    return {
      ecSignedPreKeys: ecSignedPreKeysCount,
      ecOneTimePreKeys: ecOneTimePreKeysCount,
      kyberPreKeys: kyberPreKeysCount,
      kemOneTimePreKeys: kemOneTimePreKeysCount,
    };
  }

  /**
   * Clear all sessions from storage.
   * Used during force key reset.
   */
  async clearAllSessions(): Promise<void> {
    this.sessionRecords.clear();
    this.sesameUserRecords.clear();
  }

  /**
   * Get detailed statistics about stored data.
   */
  async getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    return {
      sessions: this.sessionRecords.size,
      ecSignedPreKeys: this.ecSignedPreKeys.size,
      ecOneTimePreKeys: this.ecOneTimePreKeys.size,
      kyberPreKeys: this.kyberPreKeys.size,
      kemOneTimePreKeys: this.kemOneTimePreKeys.size,
      users: this.sesameUserRecords.size,
    };
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private getAddressKey(address: ProtocolAddress): string {
    return `${address.userId}.${address.deviceId}`;
  }

  private getContactIdentityKey(address: ProtocolAddress, identityType?: IdentityType): string {
    return `${address.userId}:${identityType ?? 'aci'}`;
  }
}
