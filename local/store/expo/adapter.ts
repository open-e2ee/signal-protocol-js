/**
 * Expo Signal Protocol Store
 *
 * Local Signal Protocol state store for Expo/React Native applications.
 * Uses:
 * - a local secret vault for the database encryption key
 * - an application-configured Expo SQLite/SQLCipher database
 *
 * This class wraps the KeyStorage implementation and provides
 * the ISignalProtocolLocalStore interface for dependency injection.
 */

import type {
  IdentityKeyPair,
  KyberPreKey,
  KemOneTimePreKey,
  EcOneTimePreKey,
  EcSignedPreKey,
  IdentityType,
  CompositeIdentityV1,
  ContactIdentityRecord,
} from '../../../keys';
import {
  encodeCompositeIdentityV1,
  UNPINNED_DEVICE_IDENTITY_KEY,
} from '../../../keys/identity';
import type {
  ISignalProtocolLocalStore,
  MessageRecord,
  SessionRecord,
  SessionState,
  SessionTrustCommit,
} from '../../../types';
import type { ProtocolAddress } from '../../../types/address';
import type { IdentityKeyChange, TrustDirection } from '../../../types/trust';
import type { DeviceRecord, UserRecord } from '../../../internal/sesame/types';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';

import { getDatabaseKeyManager } from './database-key';
import { KeyStorage } from './key-storage';
import { resolveSignalProtocolLogger, type ILogger } from '../../../logger';

/**
 * Expo Signal Protocol Store
 *
 * Provides secure storage for Signal Protocol keys using Expo's native modules.
 *
 * ## Architecture
 *
 * Two-layer encryption:
 * - **Layer 1 (secret vault)**: Single 32-byte database encryption key
 * - **Layer 2 (SQLCipher)**: Full-database encryption configured by the host
 *
 * ## Security
 *
 * - Key custody follows the configured `ISignalProtocolLocalSecretVault`
 * - Protocol records are stored in the encrypted database, not the secret vault
 * - Account reset coordinates logical record and key deletion
 * - TOFU (Trust On First Use) for contact identities
 *
 * @example
 * ```typescript
 * // Configure the Expo database bindings before creating the store.
 * const store = new ExpoSignalProtocolStore();
 *
 * // Store identity key
 * await store.storeIdentityKey(keyPair);
 *
 * // Get identity key
 * const keyPair = await store.getIdentityKey();
 * ```
 *
 * @category Key Storage
 * @see {@link ISignalProtocolLocalStore} for interface documentation
 */
export {};
export class ExpoSignalProtocolStore implements ISignalProtocolLocalStore {
  private storage: KeyStorage;
  private logger: Required<ILogger>;

  constructor(providedLogger?: ILogger) {
    this.logger = resolveSignalProtocolLogger(providedLogger);
    this.storage = new KeyStorage(this.logger);
  }

  setLogger(providedLogger?: ILogger): void {
    this.logger = resolveSignalProtocolLogger(providedLogger);
    this.storage.setLogger(this.logger);
  }

  // ============================================================================
  // Identity Key Management (Own Keys)
  // ============================================================================

  async storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void> {
    await this.storage.storeIdentityKey(keyPair, identityType);
  }

  async getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null> {
    return await this.storage.getIdentityKey(identityType);
  }

  async deleteIdentityKey(identityType?: IdentityType): Promise<void> {
    await this.storage.deleteIdentityKey(identityType);
  }

  async hasIdentityKey(identityType?: IdentityType): Promise<boolean> {
    return await this.storage.hasIdentityKey(identityType);
  }

  async getLocalRegistrationId(identityType?: IdentityType): Promise<number> {
    return await this.storage.getLocalRegistrationId(identityType);
  }

  async setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void> {
    await this.storage.setLocalRegistrationId(id, identityType);
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
    return await this.storage.saveContactIdentity(
      address,
      identity,
      identityType,
      suppliedCommitment
    );
  }

  async getContactIdentity(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): Promise<ContactIdentityRecord | null> {
    return await this.storage.getContactIdentity(address, identityType);
  }

  async acceptContactIdentityRotation(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return await this.storage.acceptContactIdentityRotationAndDeleteSessions(
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
    return await this.storage.acceptContactIdentityRotationAndDeleteSessions(
      address,
      identity,
      identityType,
      suppliedCommitment
    );
  }

  async verifyContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return await this.storage.verifyContactIdentity(
      address,
      identity,
      identityType,
      suppliedCommitment
    );
  }

  async isTrustedIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    direction: TrustDirection,
    identityType?: IdentityType
  ): Promise<boolean> {
    return await this.storage.isTrustedIdentity(
      address,
      identity,
      direction as unknown as number,
      identityType
    );
  }

  // ============================================================================
  // PreKey Management
  // ============================================================================

  async storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType?: IdentityType
  ): Promise<void> {
    await this.storage.storeEcSignedPreKey(signedPreKey, identityType);
  }

  async getEcSignedPreKey(
    keyId?: number,
    identityType?: IdentityType
  ): Promise<EcSignedPreKey | null> {
    return await this.storage.getEcSignedPreKey(keyId, identityType);
  }

  async getAllEcSignedPreKeys(identityType?: IdentityType): Promise<EcSignedPreKey[]> {
    return await this.storage.getAllEcSignedPreKeys(identityType);
  }

  async removeEcSignedPreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    return await this.storage.removeEcSignedPreKey(keyId, identityType);
  }

  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    await this.storage.storeEcOneTimePreKeys(prekeys, identityType);
  }

  async getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]> {
    return await this.storage.getEcOneTimePreKeys(identityType);
  }

  async removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void> {
    await this.storage.removeEcOneTimePreKey(preKeyId, identityType);
  }

  async storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void> {
    await this.storage.storeKyberPreKey(kyberPreKey, identityType);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    const result = await this.storage.getKyberPreKey(identityType);
    return result as KyberPreKey | null;
  }

  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void> {
    await this.storage.markKyberPreKeyUsed(
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes,
      identityType
    );
  }

  // ============================================================================
  // KEM One-Time PreKey Management (Per-Session Post-Quantum Forward Secrecy)
  // ============================================================================

  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    await this.storage.storeKemOneTimePreKeys(prekeys, identityType);
  }

  async getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]> {
    return await this.storage.getKemOneTimePreKeys(identityType);
  }

  async getKemOneTimePreKey(
    keyId: number,
    identityType?: IdentityType
  ): Promise<KemOneTimePreKey | null> {
    return await this.storage.getKemOneTimePreKey(keyId, identityType);
  }

  async removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    await this.storage.removeKemOneTimePreKey(keyId, identityType);
  }

  async getKemOneTimePreKeyCount(identityType?: IdentityType): Promise<number> {
    return await this.storage.getKemOneTimePreKeyCount(identityType);
  }

  // ============================================================================
  // Session Management (New API)
  // ============================================================================

  async storeSessionRecord(address: ProtocolAddress, record: SessionRecord): Promise<void> {
    await this.storage.storeSessionRecord(address, record);
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    await this.storage.commitSessionTrust(commit);
  }

  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    const result = await this.storage.getSessionRecord(address);
    return result;
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    await this.storage.deleteSessionRecord(address);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    // Convert null to undefined for KeyStorage
    await this.storage.archiveCurrentSession(address, newSession ?? undefined);
  }

  async getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    return await this.storage.getSessionsForUser(userId);
  }

  async hasSession(address: ProtocolAddress): Promise<boolean> {
    return await this.storage.hasSession(address);
  }

  // ============================================================================
  // Legacy Session API (Deprecated)
  // ============================================================================

  async storeSession(sessionId: string, session: SessionState): Promise<void> {
    await this.storage.storeSession(sessionId, session);
  }

  async getSession(sessionId: string): Promise<SessionState | null> {
    return await this.storage.getSession(sessionId);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.storage.deleteSession(sessionId);
  }

  // ============================================================================
  // Database Encryption
  // ============================================================================

  async getDatabaseKey(): Promise<Uint8Array> {
    const dbKeyManager = getDatabaseKeyManager(this.logger);
    return await dbKeyManager.getKeyOrThrow();
  }

  // ============================================================================
  // Utility
  // ============================================================================

  async getSessionCount(): Promise<number> {
    // Delegate to underlying storage implementation
    return await this.storage.getSessionCount();
  }

  async clearAllKeys(): Promise<void> {
    await this.storage.clearAllKeys();
  }

  async getMetadata(key: string): Promise<string | null> {
    return this.storage.getMetadata(key);
  }

  async setMetadata(key: string, value: string): Promise<void> {
    return this.storage.setMetadata(key, value);
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================
  // SESAME sessions are stored locally, following the Signal Protocol SESAME specification.
  // The server only stores device registry, prekeys, and message mailbox.

  /**
   * Helper to get a contact's pinned identity as canonical DeviceRecord bytes.
   *
   * Returns the whole composite tuple, not the X25519 half: a device pinned to
   * the DH key alone would accept a peer that swapped its Ed25519 signing key,
   * and would compare unequal against every other producer of these bytes.
   */
  private async getContactIdentityBytes(address: ProtocolAddress): Promise<Uint8Array | null> {
    const record = await this.getContactIdentity(address);
    if (!record) return null;
    return encodeCompositeIdentityV1(record.identity);
  }

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    // UserRecords are stored locally - get all sessions for this user
    const sessions = await this.getSessionsForUser(userId);
    if (sessions.length === 0) return null;

    // Build devices map from sessions
    const devices = new Map<number, DeviceRecord>();
    const now = Date.now();

    for (const session of sessions) {
      // Extract deviceId from session's remoteAddress
      const deviceId = session.currentSession?.remoteAddress?.deviceId;
      if (deviceId === undefined) continue;

      // Build DeviceRecord from session (similar to getDeviceRecord())
      const address = { userId, deviceId };
      const identityKey = await this.getContactIdentityBytes(address);
      devices.set(deviceId, {
        userId,
        deviceId,
        identityKey: identityKey ?? UNPINNED_DEVICE_IDENTITY_KEY,
        session,
        createdAt: session.metadata?.createdAt ?? now,
        updatedAt: now,
      });
    }

    return {
      userId,
      devices,
      createdAt: now,
      updatedAt: now,
    };
  }

  async setUserRecord(_userId: string, _record: UserRecord): Promise<void> {
    // UserRecords are aggregates of DeviceRecords - store via setDeviceRecord
    // This is intentionally a no-op as individual devices are stored separately
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    // DeviceRecords are stored locally via session storage
    const address = { userId, deviceId };
    const sessionRecord = await this.getSessionRecord(address);
    if (!sessionRecord) return null;

    // Load actual identity key from contact identity storage
    const identityKey = await this.getContactIdentityBytes(address);
    const now = Date.now();

    return {
      userId,
      deviceId,
      identityKey: identityKey ?? UNPINNED_DEVICE_IDENTITY_KEY,
      session: sessionRecord,
      createdAt: sessionRecord.metadata?.createdAt ?? now,
      updatedAt: now,
    };
  }

  async setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void> {
    const address = { userId, deviceId };

    // Store session locally
    if (record.session) {
      await this.storeSessionRecord(address, record.session);
    }

    // Generic SESAME DeviceRecord identity bytes do not carry the Ed25519
    // component, so they cannot mutate composite trust storage.
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    // Delete local session for this device
    const address = { userId, deviceId };
    await this.deleteSessionRecord(address);
  }

  async getDeviceSession(userId: string, deviceId: number): Promise<SessionRecord | null> {
    // Sessions are stored locally via ProtocolAddress
    const address = { userId, deviceId };
    return this.getSessionRecord(address);
  }

  async setDeviceSession(userId: string, deviceId: number, session: SessionRecord): Promise<void> {
    // Sessions are stored locally via ProtocolAddress
    const address = { userId, deviceId };
    await this.storeSessionRecord(address, session);
  }

  /**
   * Delete stale device records that have no active sessions.
   *
   * A device is considered stale if:
   * 1. It has no active session AND no archived sessions
   * 2. Its age exceeds maxLatency
   *
   * @param maxLatency - Maximum age in milliseconds (default: 30 days)
   * @returns Number of device records deleted
   */
  async deleteStaleRecords(maxLatency: number): Promise<number> {
    // Delete device records with no active sessions and age > maxLatency
    const now = Date.now();
    let deletedCount = 0;

    const userIds = await this.getAllUserIds();

    for (const userId of userIds) {
      const deviceIds = await this.getSesameDeviceIds(userId);

      for (const deviceId of deviceIds) {
        try {
          const deviceRecord = await this.getDeviceRecord(userId, deviceId);
          if (!deviceRecord) continue;

          // Device is stale if:
          // 1. No active session AND no archived sessions
          // 2. Age > maxLatency
          const hasNoSessions =
            !deviceRecord.session?.currentSession &&
            Object.keys(deviceRecord.session?.archivedSessions ?? {}).length === 0;
          const deviceAge = now - deviceRecord.createdAt;

          if (hasNoSessions && deviceAge > maxLatency) {
            await this.deleteDeviceRecord(userId, deviceId);
            deletedCount++;
          }
        } catch {
          // Continue processing other devices on error
          continue;
        }
      }
    }

    return deletedCount;
  }

  /**
   * Delete expired sessions based on age.
   *
   * Sessions are considered expired if their age exceeds maxRecv.
   * Following SESAME spec, default maxRecv is 180 days.
   *
   * @param maxRecv - Maximum session age in milliseconds (default: 180 days)
   * @returns Number of sessions deleted
   */
  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    // Delete sessions older than maxRecv (default 180 days)
    const now = Date.now();
    let deletedCount = 0;

    const userIds = await this.getAllUserIds();

    for (const userId of userIds) {
      const deviceIds = await this.getSesameDeviceIds(userId);

      for (const deviceId of deviceIds) {
        try {
          const address = { userId, deviceId };
          const sessionRecord = await this.getSessionRecord(address);
          if (!sessionRecord) continue;

          const createdAt = sessionRecord.metadata?.createdAt ?? now;
          const sessionAge = now - createdAt;

          if (sessionAge > maxRecv) {
            // Delete the expired session
            await this.deleteSessionRecord(address);
            deletedCount++;
          }
        } catch {
          // Continue processing other devices on error
          continue;
        }
      }
    }

    return deletedCount;
  }

  /**
   * Get all unique user IDs that have sessions in local storage.
   *
   * Extracts user IDs from session IDs stored in Signal Protocol format (userId:deviceId).
   * Only includes entries where the deviceId portion is a valid non-negative integer.
   *
   * @returns Array of unique user IDs
   */
  async getAllUserIds(): Promise<string[]> {
    // Get all sessions and extract unique user IDs
    // Uses Signal Protocol standard colon separator (userId:deviceId)
    const allSessionIds = await this.storage.getAllSessionIds();
    const userIds = new Set<string>();

    for (const sessionId of allSessionIds) {
      // Session IDs use Signal Protocol format: "userId:deviceId"
      const colonIndex = sessionId.lastIndexOf(':');
      if (colonIndex > 0) {
        // Validate that the portion after colon is a valid deviceId (numeric)
        const deviceIdStr = sessionId.substring(colonIndex + 1);
        const deviceId = parseInt(deviceIdStr, 10);
        if (!isNaN(deviceId) && deviceId >= 0) {
          userIds.add(sessionId.substring(0, colonIndex));
        }
      }
    }

    return Array.from(userIds);
  }

  /**
   * Get all device IDs for a specific user from local session storage.
   *
   * Queries sessions matching the user ID and extracts unique device IDs.
   * Session IDs follow Signal Protocol format (userId:deviceId).
   *
   * @param userId - User ID to query devices for
   * @returns Array of device IDs (unique, non-negative integers)
   */
  async getSesameDeviceIds(userId: string): Promise<number[]> {
    // Get session IDs for this user using KeyStorage's method
    // Uses Signal Protocol standard colon separator (userId:deviceId)
    const sessionIds = await this.storage.getSessionIdsForUser(userId);
    const deviceIds: number[] = [];

    for (const sessionId of sessionIds) {
      // Session IDs use Signal Protocol format: "userId:deviceId"
      const colonIndex = sessionId.lastIndexOf(':');
      if (colonIndex > 0) {
        const deviceIdStr = sessionId.substring(colonIndex + 1);
        const deviceId = parseInt(deviceIdStr, 10);
        if (!isNaN(deviceId) && !deviceIds.includes(deviceId)) {
          deviceIds.push(deviceId);
        }
      }
    }

    return deviceIds;
  }

  // ============================================================================
  // Sender Keys Management (Group Messaging)
  // ============================================================================
  // Sender key state is device-local. The chain key and the sender's private
  // signature key are enough to read and to forge every message on that chain,
  // so they never leave the device — the reference keeps its sender key store
  // local for the same reason. SQLCipher encrypts the database file that holds
  // them.

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

  /**
   * Store a sender key record (current state first, then the superseded states
   * the rotation window still needs).
   *
   * The whole record is one row, so current and previous states can never be
   * written apart from one another.
   */
  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void> {
    if (states.length === 0) return;

    const { createSenderKey } = await import('./models/sender-key');
    await createSenderKey({ groupId, senderId: userId, deviceId, states }).save();
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    const { getSenderKey } = await import('./models/sender-key');
    const row = await getSenderKey(groupId, userId, deviceId);
    if (!row) return null;

    const states = row.states;
    if (states.length === 0) {
      // The record column failed to parse. Report "no sender key" so the
      // caller asks for a fresh distribution message instead of throwing.
      this.logger.warn('Corrupted sender key record', { groupId, userId, deviceId });
      return null;
    }

    return states;
  }

  async resolveGroupForSenderKeyId(
    senderKeyId: string,
    userId: string,
    deviceId: number
  ): Promise<string | null> {
    const { findGroupBySenderKeyId } = await import('./models/sender-key');
    return findGroupBySenderKeyId(senderKeyId, userId, deviceId);
  }

  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    const { deleteSenderKey } = await import('./models/sender-key');
    await deleteSenderKey(groupId, userId, deviceId);
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    const { getSenderKeysByGroup } = await import('./models/sender-key');
    const rows = await getSenderKeysByGroup(groupId);

    const states: SenderKeyState[] = [];
    for (const row of rows) {
      const current = row.currentState;
      if (current) states.push(current);
    }
    return states;
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    const { deleteSenderKeysByGroup } = await import('./models/sender-key');
    return deleteSenderKeysByGroup(groupId);
  }

  // ============================================================================
  // Skipped Sender Keys (Out-of-Order Message Support)
  // ============================================================================
  // These are the message keys themselves. Same rule as the chain key above:
  // device-local only.

  async storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: { iv: string; cipherKey: string }
  ): Promise<void> {
    const { getDrizzle, skippedSenderKeys } = await import('./db');
    const db = await getDrizzle();

    await db
      .insert(skippedSenderKeys)
      .values({
        groupId,
        senderId,
        senderDeviceId,
        chainIndex,
        cipherKey: messageKey.cipherKey,
        iv: messageKey.iv,
        createdAt: Date.now(),
      })
      .onConflictDoUpdate({
        target: [
          skippedSenderKeys.groupId,
          skippedSenderKeys.senderId,
          skippedSenderKeys.senderDeviceId,
          skippedSenderKeys.chainIndex,
        ],
        set: { cipherKey: messageKey.cipherKey, iv: messageKey.iv },
      });
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<{ iv: string; cipherKey: string } | null> {
    const { getDrizzle, skippedSenderKeys, eq, and } = await import('./db');
    const db = await getDrizzle();

    const results = await db
      .select({ iv: skippedSenderKeys.iv, cipherKey: skippedSenderKeys.cipherKey })
      .from(skippedSenderKeys)
      .where(
        and(
          eq(skippedSenderKeys.groupId, groupId),
          eq(skippedSenderKeys.senderId, senderId),
          eq(skippedSenderKeys.senderDeviceId, senderDeviceId),
          eq(skippedSenderKeys.chainIndex, chainIndex)
        )
      )
      .limit(1);

    const row = results[0];
    return row ? { iv: row.iv, cipherKey: row.cipherKey } : null;
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    const { getDrizzle, skippedSenderKeys, eq, and } = await import('./db');
    const db = await getDrizzle();

    await db
      .delete(skippedSenderKeys)
      .where(
        and(
          eq(skippedSenderKeys.groupId, groupId),
          eq(skippedSenderKeys.senderId, senderId),
          eq(skippedSenderKeys.senderDeviceId, senderDeviceId),
          eq(skippedSenderKeys.chainIndex, chainIndex)
        )
      );
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    const { getDrizzle, skippedSenderKeys, eq, and, count } = await import('./db');
    const db = await getDrizzle();

    const results = await db
      .select({ count: count() })
      .from(skippedSenderKeys)
      .where(
        and(
          eq(skippedSenderKeys.groupId, groupId),
          eq(skippedSenderKeys.senderId, senderId),
          eq(skippedSenderKeys.senderDeviceId, senderDeviceId)
        )
      );

    return results[0]?.count ?? 0;
  }

  /**
   * Evict the oldest skipped keys for a sender, so a peer cannot grow this
   * table without bound by sending messages that skip ever further ahead.
   *
   * Oldest by chain index, not by insertion time: index order is the order the
   * sender ratcheted, so the lowest index is the key least likely to still
   * have a message in flight behind it.
   */
  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    if (count <= 0) return 0;

    const { getDrizzle, skippedSenderKeys, eq, and, asc, inArray } = await import('./db');
    const db = await getDrizzle();

    const oldest = await db
      .select({ chainIndex: skippedSenderKeys.chainIndex })
      .from(skippedSenderKeys)
      .where(
        and(
          eq(skippedSenderKeys.groupId, groupId),
          eq(skippedSenderKeys.senderId, senderId),
          eq(skippedSenderKeys.senderDeviceId, senderDeviceId)
        )
      )
      .orderBy(asc(skippedSenderKeys.chainIndex))
      .limit(count);

    if (oldest.length === 0) return 0;

    await db.delete(skippedSenderKeys).where(
      and(
        eq(skippedSenderKeys.groupId, groupId),
        eq(skippedSenderKeys.senderId, senderId),
        eq(skippedSenderKeys.senderDeviceId, senderDeviceId),
        inArray(
          skippedSenderKeys.chainIndex,
          oldest.map((row) => row.chainIndex)
        )
      )
    );

    return oldest.length;
  }

  // ============================================================================
  // Message Record Storage (SESAME Retry Request Support)
  // ============================================================================
  // Retry records are indexed by the client timestamp assigned before encryption.
  // The primary lookup method is getMessageRecord(sessionId, timestamp).

  async storeMessageRecord(record: MessageRecord): Promise<void> {
    await this.storage.storeMessageRecord(record);
  }

  /**
   * Get a message record by session and timestamp (PRIMARY method).
   * Per Signal Protocol, messages are identified by client timestamp.
   */
  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    return await this.storage.getMessageRecord(sessionId, timestamp);
  }

  /**
   * Delete a message record by session and timestamp (PRIMARY method).
   * Called when processing delivery receipts to clean up confirmed messages.
   */
  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    await this.storage.deleteMessageRecord(sessionId, timestamp);
  }

  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    return await this.storage.deleteExpiredMessageRecords(maxAgeMs);
  }

  async clearAllMessageRecords(): Promise<number> {
    return await this.storage.clearAllMessageRecords();
  }

  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    return await this.storage.deleteMessageRecordsForSession(sessionId);
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
    return await this.storage.getEcSignedPreKeyMaxId(identityType);
  }

  /**
   * Get the maximum Kyber prekey ID in storage.
   * Used to generate new keyIds that won't collide with existing ones.
   *
   * @returns The highest Kyber prekey ID, or 0 if none exist
   */
  async getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    return await this.storage.getKyberPreKeyMaxId(identityType);
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
    return await this.storage.deleteAllPreKeys(identityType);
  }

  /**
   * Clear all sessions from storage.
   * Used during force key reset.
   */
  async clearAllSessions(): Promise<void> {
    return await this.storage.clearAllSessions();
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
    return await this.storage.getDetailedStats();
  }
}
