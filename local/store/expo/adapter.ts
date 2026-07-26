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
import type { ISignalProtocolRemoteSenderStateStore } from '../../../remote/relay/types';
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
  // Backend for SESAME/SenderKey operations (Convex relay server)
  private backend?: ISignalProtocolRemoteSenderStateStore;

  constructor(backend?: ISignalProtocolRemoteSenderStateStore, providedLogger?: ILogger) {
    this.logger = resolveSignalProtocolLogger(providedLogger);
    this.storage = new KeyStorage(this.logger);
    this.backend = backend;
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

  /**
   * Helper to require backend for Sender Key operations.
   * Note: SESAME operations are now local-only and don't require backend.
   */
  private requireBackend(operation: string): ISignalProtocolRemoteSenderStateStore {
    if (!this.backend) {
      throw new Error(
        `${operation} requires a backend adapter. ` +
          `Pass a ConvexSignalProtocolRelayServer to the key store constructor: ` +
          `new ExpoSignalProtocolStore(relay)`
      );
    }
    return this.backend;
  }

  private requireBackendMethod<K extends keyof ISignalProtocolRemoteSenderStateStore>(
    operation: string,
    method: K
  ): NonNullable<ISignalProtocolRemoteSenderStateStore[K]> {
    const backend = this.requireBackend(operation);
    const fn = backend[method];
    if (!fn) {
      throw new Error(
        `${operation} requires backend.${method}() method. ` +
          `The provided backend does not implement this method.`
      );
    }
    return fn as NonNullable<ISignalProtocolRemoteSenderStateStore[K]>;
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
  // Sender Keys require server-side storage for group message coordination

  async storeSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    state: SenderKeyState
  ): Promise<void> {
    const fn = this.requireBackendMethod('storeSenderKey', 'storeSenderKey');
    await fn(
      state.senderKeyId || `${groupId}:${userId}:${deviceId}`,
      groupId,
      userId,
      deviceId,
      state.chainKey || '',
      state.signatureKey || '',
      state.chainIndex || 0,
      state.generation || 0
    );
  }

  async getSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null> {
    const fn = this.requireBackendMethod('getSenderKey', 'loadSenderKeyForDevice');
    return (await fn(groupId, userId, deviceId)) ?? null;
  }

  /**
   * Store sender key record (current + previous states).
   *
   * Server and local writes are independent — not atomic. If the local
   * SQLite write fails after the server write succeeds, previousStates
   * are lost. This is acceptable: lost previous states only affect
   * in-flight messages during a key rotation window, and the next
   * successful write will restore them.
   */
  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void> {
    if (states.length === 0) return;

    const currentState = states[0];
    const previousStates = states.length > 1 ? states.slice(1) : [];

    // Sync current state to server via backend
    await this.storeSenderKey(groupId, userId, deviceId, currentState);

    // Upsert locally with previousStates (handles both insert and update)
    const { SenderKey } = await import('./models/sender-key');
    const now = Date.now();
    const senderKey = new SenderKey({
      id: 0,
      distributionId: groupId,
      senderId: userId,
      deviceId,
      chainKey: currentState.chainKey || '',
      iteration: currentState.chainIndex || 0,
      previousStates: previousStates.length > 0 ? JSON.stringify(previousStates) : null,
      createdAt: now,
      updatedAt: now,
    });
    await senderKey.save();
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    // Get full current state from server via backend
    const currentState = await this.getSenderKey(groupId, userId, deviceId);
    if (!currentState) return null;

    // Load previous states from local database
    const { getDrizzle, senderKeys, eq, and } = await import('./db');
    const db = await getDrizzle();
    const results = await db
      .select({ previousStates: senderKeys.previousStates })
      .from(senderKeys)
      .where(
        and(
          eq(senderKeys.distributionId, groupId),
          eq(senderKeys.senderId, userId),
          eq(senderKeys.deviceId, deviceId)
        )
      )
      .limit(1);

    const previousStatesJson = results[0]?.previousStates;
    let previousStates: SenderKeyState[] = [];
    if (previousStatesJson) {
      try {
        previousStates = JSON.parse(previousStatesJson);
      } catch {
        // Corrupted previousStates column — degrade to current state only.
        // This can happen if an interrupted write truncated the JSON.
        this.logger.warn('Corrupted previousStates JSON for sender key', {
          groupId,
          userId,
          deviceId,
        });
      }
    }

    return [currentState, ...previousStates];
  }

  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    const fn = this.requireBackendMethod('deleteSenderKey', 'deleteSenderKey');
    const senderKeyId = `${groupId}:${userId}:${deviceId}`;
    await fn(senderKeyId);
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    const fn = this.requireBackendMethod('getAllSenderKeysForGroup', 'loadAllSenderKeysForGroup');
    return (await fn(groupId)) || [];
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    const fn = this.requireBackendMethod(
      'deleteAllSenderKeysForGroup',
      'deleteAllSenderKeysForGroup'
    );
    return (await fn(groupId)) || 0;
  }

  // ============================================================================
  // Skipped Sender Keys (Out-of-Order Message Support)
  // ============================================================================

  async storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: { iv: string; cipherKey: string }
  ): Promise<void> {
    const fn = this.requireBackendMethod('storeSkippedSenderKey', 'storeSkippedSenderKey');
    await fn(groupId, senderId, senderDeviceId, chainIndex, messageKey.cipherKey, messageKey.iv);
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<{ iv: string; cipherKey: string } | null> {
    const fn = this.requireBackendMethod('getSkippedSenderKey', 'getSkippedSenderKey');
    const key = await fn(groupId, senderId, senderDeviceId, chainIndex);
    if (!key) return null;
    return { iv: key.iv, cipherKey: key.cipherKey };
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    const fn = this.requireBackendMethod('deleteSkippedSenderKey', 'deleteSkippedSenderKey');
    await fn(groupId, senderId, senderDeviceId, chainIndex);
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    const fn = this.requireBackendMethod('countSkippedSenderKeys', 'countSkippedSenderKeys');
    return (await fn(groupId, senderId, senderDeviceId)) || 0;
  }

  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    const fn = this.requireBackendMethod(
      'deleteOldestSkippedSenderKeys',
      'deleteOldestSkippedSenderKeys'
    );
    return (await fn(groupId, senderId, senderDeviceId, count)) || 0;
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
