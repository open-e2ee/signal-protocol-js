/**
 * The Signal Protocol local store over one SQLite executor.
 *
 * It implements SignalProtocolLocalStore on the key storage of the same
 * executor, and adds the SESAME device records and the group sender keys. A
 * platform entry opens the database and supplies the executor.
 */

import type {
  ReceiveWorkMetadataWrite,
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  ReceiveWorkUsage,
  SenderKeyReceiveCommit,
} from '../../../types';
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
import type {
  LocalStoreProtection,
  SignalProtocolLocalStore,
  RetainedKyberPreKey,
  MessageRecord,
  NewSendLogPayload,
  SendLogDevice,
  SendLogEntry,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
  SessionRecord,
  SessionState,
  SessionTrustCommit,
  SenderKeyHandoffDevice,
  SenderKeyHandoffRecord,
  SenderKeyRecordWriteOptions,
  SetDeviceRecordOptions,
} from '../../../types';
import type { ProtocolAddress } from '../../../types/address';
import type { IdentityKeyChange, TrustDirection } from '../../../types/trust';
import {
  isExpiredRemovedDevice,
  type DeviceRecord,
  type UserRecord,
} from '../../../internal/sesame/types';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import { resolveSignalProtocolLogger, type Logger } from '../../../logger';

import type { SqliteExecutor } from './driver';
import { SqliteKeyStorage, type SqliteKeyStorageOptions } from './key-storage';
import { legacyReceivedContentSource } from './key-storage/metadata';
import { writeReceiveWork } from './key-storage/receive-work';
import * as handoffs from './key-storage/sender-key-handoff';
import type { SqliteRootExecutor } from './executor';
import { convertLegacyReceivedContent, LEGACY_RECEIVED_CONTENT_UNREADABLE } from '../receive-work';
import { withDeviceRecordLocks } from '../../../internal/session/record-locks';
import { withSession } from '../device-record';
import {
  countSkippedSenderKeys,
  createSenderKey,
  deleteOldestSkippedSenderKeys,
  deleteSenderKey,
  deleteSenderKeysByGroup,
  deleteSesameDevice,
  deleteSkippedSenderKey,
  findGroupBySenderKeyId,
  getSenderKey,
  getSenderKeysByGroup,
  getSesameUserIds,
  getSesameUserRecord,
  getSkippedSenderKey,
  saveSesameDevice,
  saveSesameUserRecord,
  storeSkippedSenderKey,
} from './models';

export interface SqliteSignalProtocolStoreOptions extends SqliteKeyStorageOptions {
  /**
   * The protection that the platform entry read when it opened the database.
   * Default: no encryption and no key.
   */
  protection?: LocalStoreProtection;
}

const UNPROTECTED: LocalStoreProtection = Object.freeze({ atRest: 'none', keyCustody: 'none' });

/**
 * @category Key Storage
 * @see {@link SignalProtocolLocalStore} for interface documentation
 */
export class SqliteSignalProtocolStore implements SignalProtocolLocalStore {
  readonly protection: LocalStoreProtection;
  protected readonly storage: SqliteKeyStorage;
  protected logger: Required<Logger>;

  constructor(db: SqliteExecutor, options: SqliteSignalProtocolStoreOptions = {}) {
    this.protection = options.protection ? Object.freeze({ ...options.protection }) : UNPROTECTED;
    this.logger = resolveSignalProtocolLogger(options.logger);
    this.storage = new SqliteKeyStorage(db, { logger: this.logger });
  }

  /** The executor that every operation of this store uses. */
  protected get db(): SqliteExecutor {
    return this.storage.db;
  }

  /**
   * Run a key storage write and the handoff row deletes that it causes in one
   * transaction. The key storage operations open savepoints inside it.
   */
  private inTransaction<T>(
    operation: (storage: SqliteKeyStorage, tx: SqliteExecutor) => Promise<T>
  ): Promise<T> {
    return this.db.transaction((tx) =>
      operation(new SqliteKeyStorage(tx, { logger: this.logger }), tx)
    );
  }

  setLogger(providedLogger?: Logger): void {
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
    return this.inTransaction(async (storage, tx) => {
      const replacement = await storage.acceptContactIdentityRotationAndDeleteSessions(
        address,
        identity,
        identityType,
        suppliedCommitment
      );
      await handoffs.deleteAccountSenderKeyHandoffs(tx, address.userId);
      return replacement;
    });
  }

  async acceptContactIdentityRotationAndDeleteSessions(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return this.inTransaction(async (storage, tx) => {
      const replacement = await storage.acceptContactIdentityRotationAndDeleteSessions(
        address,
        identity,
        identityType,
        suppliedCommitment
      );
      await handoffs.deleteAccountSenderKeyHandoffs(tx, address.userId);
      return replacement;
    });
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

  async getKyberPreKeyById(
    keyId: number,
    identityType?: IdentityType
  ): Promise<RetainedKyberPreKey | null> {
    return await this.storage.getKyberPreKeyById(keyId, identityType);
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
    const invalidation = commit.senderKeyHandoffInvalidation;
    if (!invalidation) {
      await this.storage.commitSessionTrust(commit);
      return;
    }
    await this.inTransaction(async (storage, tx) => {
      await storage.commitSessionTrust(commit);
      await handoffs.deleteDeviceSenderKeyHandoffs(tx, invalidation);
    });
  }

  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    const result = await this.storage.getSessionRecord(address);
    return result;
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    await this.inTransaction(async (storage, tx) => {
      await storage.deleteSessionRecord(address);
      await handoffs.deleteDeviceSenderKeyHandoffs(tx, address);
    });
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    await this.inTransaction(async (storage, tx) => {
      // Convert null to undefined for KeyStorage
      await storage.archiveCurrentSession(address, newSession ?? undefined);
      await handoffs.deleteDeviceSenderKeyHandoffs(tx, address);
    });
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

  async deleteMetadata(key: string): Promise<void> {
    return this.storage.deleteMetadata(key);
  }

  async compareAndSetMetadata(
    key: string,
    expected: string | null,
    value: string | null
  ): Promise<boolean> {
    return this.storage.compareAndSetMetadata(key, expected, value);
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  // ============================================================================
  // A device's session lives only in the sessions table; see
  // `./models/sesame-user-record`.

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    const record = await getSesameUserRecord(this.db, userId);
    if (!record) return null;
    for (const [deviceId, device] of record.devices) {
      const session = await this.getSessionRecord({ userId, deviceId });
      record.devices.set(deviceId, withSession(userId, deviceId, device, session)!);
    }
    return record;
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    await saveSesameUserRecord(this.db, userId, record);
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    const stored = (await getSesameUserRecord(this.db, userId))?.devices.get(deviceId) ?? null;
    const session = await this.getSessionRecord({ userId, deviceId });
    return withSession(userId, deviceId, stored, session);
  }

  async setDeviceRecord(
    userId: string,
    deviceId: number,
    record: DeviceRecord,
    options?: SetDeviceRecordOptions
  ): Promise<void> {
    const invalidation = options?.senderKeyHandoffInvalidation;
    if (!invalidation) {
      await saveSesameDevice(this.db, userId, deviceId, record);
      return;
    }
    await this.db.transaction(async (tx) => {
      await saveSesameDevice(tx, userId, deviceId, record);
      await handoffs.deleteDeviceSenderKeyHandoffs(tx, invalidation);
    });
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    await this.db.transaction(async (tx) => {
      await deleteSesameDevice(tx, userId, deviceId);
      await handoffs.deleteDeviceSenderKeyHandoffs(tx, { userId, deviceId });
    });
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

    // The scan takes no lock. Each device is decided again under the locks of
    // its records, so a write that lands after the scan is kept.
    for (const userId of userIds) {
      const deviceIds = await this.getSesameDeviceIds(userId);

      for (const deviceId of deviceIds) {
        try {
          const deviceRecord = await this.getDeviceRecord(userId, deviceId);
          if (!deviceRecord || !isStaleDeviceRecord(deviceRecord, now, maxLatency)) continue;

          const deleted = await withDeviceRecordLocks(this, userId, deviceId, async () => {
            const current = await this.getDeviceRecord(userId, deviceId);
            if (!current || !isStaleDeviceRecord(current, now, maxLatency)) return false;
            await this.deleteDeviceRecord(userId, deviceId);
            return true;
          });
          if (deleted) deletedCount++;
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

    // The scan takes no lock. Each session is decided again under the locks
    // of its device, so a session that is written after the scan is kept.
    for (const userId of userIds) {
      const deviceIds = await this.getSesameDeviceIds(userId);

      for (const deviceId of deviceIds) {
        try {
          const address = { userId, deviceId };
          const sessionRecord = await this.getSessionRecord(address);
          if (!sessionRecord || !isExpiredSession(sessionRecord, now, maxRecv)) continue;

          const deleted = await withDeviceRecordLocks(this, userId, deviceId, async () => {
            const current = await this.getSessionRecord(address);
            if (!current || !isExpiredSession(current, now, maxRecv)) return false;
            // Delete the expired session
            await this.deleteSessionRecord(address);
            return true;
          });
          if (deleted) deletedCount++;
        } catch {
          // Continue processing other devices on error
          continue;
        }
      }
    }

    return deletedCount;
  }

  /** The users that have a stored SESAME user record. */
  async getAllUserIds(): Promise<string[]> {
    return getSesameUserIds(this.db);
  }

  /** The devices in the user's stored SESAME user record. */
  async getSesameDeviceIds(userId: string): Promise<number[]> {
    const record = await getSesameUserRecord(this.db, userId);
    return record ? Array.from(record.devices.keys()) : [];
  }

  // ============================================================================
  // Sender Keys Management (Group Messaging)
  // ============================================================================
  // Sender key state is device-local. The chain key and the sender's private
  // signature key are enough to read and to forge every message on that chain.
  // They never leave the device. The reference keeps its sender key store
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
    states: SenderKeyState[],
    receive?: SenderKeyReceiveCommit,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void> {
    if (states.length === 0) return;

    await this.db.transaction(async (tx) => {
      await createSenderKey({ groupId, senderId: userId, deviceId, states }).save(tx);
      if (receive) {
        if (receive.skippedKeys) {
          for (const skipped of receive.skippedKeys.keys) {
            const count = await countSkippedSenderKeys(tx, groupId, userId, deviceId);
            await deleteOldestSkippedSenderKeys(
              tx,
              groupId,
              userId,
              deviceId,
              count - Math.max(0, receive.skippedKeys.maxSkippedKeys - 1)
            );
            await storeSkippedSenderKey(
              tx,
              groupId,
              userId,
              deviceId,
              skipped.senderKeyId,
              skipped.chainIndex,
              skipped.messageKey
            );
          }
        }
        if (receive.work) await writeReceiveWork(tx, receive.work);
        if (receive.consumedSkippedKey !== undefined)
          await deleteSkippedSenderKey(
            tx,
            groupId,
            userId,
            deviceId,
            receive.consumedSkippedKey.senderKeyId,
            receive.consumedSkippedKey.chainIndex
          );
      }
      if (options?.deleteSenderKeyHandoffs) {
        await handoffs.deleteGroupSenderKeyHandoffs(tx, groupId);
      }
    });
  }

  // ============================================================================
  // Sender-Key Handoff Ledger
  // ============================================================================

  async recordSenderKeyHandoff(record: SenderKeyHandoffRecord): Promise<void> {
    await handoffs.recordSenderKeyHandoff(this.db, record);
  }

  async listSenderKeyHandoffs(
    groupId: string,
    generation: number
  ): Promise<SenderKeyHandoffRecord[]> {
    return handoffs.listSenderKeyHandoffs(this.db, groupId, generation);
  }

  async invalidateSenderKeyHandoff(
    groupId: string,
    device: SenderKeyHandoffDevice
  ): Promise<boolean> {
    return (await handoffs.deleteDeviceSenderKeyHandoffsInGroup(this.db, groupId, device)) > 0;
  }

  async invalidateAccountSenderKeyHandoffs(userId: string): Promise<boolean> {
    return (await handoffs.deleteAccountSenderKeyHandoffs(this.db, userId)) > 0;
  }

  async listSenderKeyHandoffGroupIds(): Promise<string[]> {
    return handoffs.listSenderKeyHandoffGroupIds(this.db);
  }

  async retainSenderKeyHandoffs(groupId: string, senderKeyId: string | null): Promise<number> {
    return handoffs.retainSenderKeyHandoffs(this.db, groupId, senderKeyId);
  }

  async getReceiveWork(workId: string): Promise<ReceiveWorkRecord | null> {
    return this.storage.getReceiveWork(workId);
  }

  async putReceiveWork(
    record: ReceiveWorkRecord,
    expectedRevision: number | null
  ): Promise<boolean> {
    return this.storage.putReceiveWork(record, expectedRevision);
  }

  async listReceiveWork(query?: ReceiveWorkQuery): Promise<ReceiveWorkRecord[]> {
    return this.storage.listReceiveWork(query);
  }

  async receiveWorkUsage(query?: { groupId?: string }): Promise<ReceiveWorkUsage> {
    return this.storage.receiveWorkUsage(query);
  }

  async completeReceiveWork(
    workId: string,
    expectedRevision: number,
    metadata?: readonly ReceiveWorkMetadataWrite[]
  ): Promise<boolean> {
    return this.storage.completeReceiveWork(workId, expectedRevision, metadata);
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    const row = await getSenderKey(this.db, groupId, userId, deviceId);
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
    return findGroupBySenderKeyId(this.db, senderKeyId, userId, deviceId);
  }

  async deleteSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void> {
    if (!options?.deleteSenderKeyHandoffs) {
      await deleteSenderKey(this.db, groupId, userId, deviceId);
      return;
    }
    await this.db.transaction(async (tx) => {
      await deleteSenderKey(tx, groupId, userId, deviceId);
      await handoffs.deleteGroupSenderKeyHandoffs(tx, groupId);
    });
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    const rows = await getSenderKeysByGroup(this.db, groupId);

    const states: SenderKeyState[] = [];
    for (const row of rows) {
      const current = row.currentState;
      if (current) states.push(current);
    }
    return states;
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    return this.db.transaction(async (tx) => {
      const deleted = await deleteSenderKeysByGroup(tx, groupId);
      await handoffs.deleteGroupSenderKeyHandoffs(tx, groupId);
      return deleted;
    });
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
    senderKeyId: string,
    chainIndex: number,
    messageKey: { iv: string; cipherKey: string }
  ): Promise<void> {
    await storeSkippedSenderKey(
      this.db,
      groupId,
      senderId,
      senderDeviceId,
      senderKeyId,
      chainIndex,
      messageKey
    );
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
    chainIndex: number
  ): Promise<{ iv: string; cipherKey: string } | null> {
    return await getSkippedSenderKey(
      this.db,
      groupId,
      senderId,
      senderDeviceId,
      senderKeyId,
      chainIndex
    );
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
    chainIndex: number
  ): Promise<void> {
    await deleteSkippedSenderKey(
      this.db,
      groupId,
      senderId,
      senderDeviceId,
      senderKeyId,
      chainIndex
    );
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    return await countSkippedSenderKeys(this.db, groupId, senderId, senderDeviceId);
  }

  /**
   * Evict the oldest skipped keys for a sender, so a peer cannot grow this
   * table without bound by sending messages that skip ever further ahead.
   *
   * Oldest by chain index, not by insertion time. Index order is the order the
   * sender ratcheted. The lowest index is therefore the key least likely to
   * still have a message in flight behind it.
   */
  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    return await deleteOldestSkippedSenderKeys(
      this.db,
      groupId,
      senderId,
      senderDeviceId,
      count
    );
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
   * The client calls it after an E2EE delivery receipt from the recipient
   * device, for an expired record at a retry request, and for a record that
   * it must not resend: a null message, or a sender key distribution alone.
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

  async rewriteMessageRecords(rewrite: (record: MessageRecord) => string | null): Promise<number> {
    return await this.storage.rewriteMessageRecords(rewrite);
  }

  // ============================================================================
  // Send Log (resendable group content)
  // ============================================================================

  async storeSendLogEntry(
    payload: NewSendLogPayload,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    await this.storage.storeSendLogEntry(payload, recipients);
  }

  async appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    await this.storage.appendSendLogRecipients(clientMessageId, recipients);
  }

  async markSendLogComplete(clientMessageId: string): Promise<void> {
    await this.storage.markSendLogComplete(clientMessageId);
  }

  async getSendLogEntry(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<SendLogEntry | null> {
    return await this.storage.getSendLogEntry(clientMessageId, recipient);
  }

  async findSendLogEntries(
    recipient: SendLogDevice,
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    return await this.storage.findSendLogEntries(recipient, clientTimestamp);
  }

  async getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    return await this.storage.getSendLogRecipients(clientMessageId);
  }

  async deleteSendLogRecipient(clientMessageId: string, recipient: SendLogDevice): Promise<boolean> {
    return await this.storage.deleteSendLogRecipient(clientMessageId, recipient);
  }

  async deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    return await this.storage.deleteSendLogRecipientsByTimestamp(recipient, clientTimestamps);
  }

  async incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    return await this.storage.incrementSendLogResendCount(clientMessageId, recipient);
  }

  async deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    return await this.storage.deleteSendLogEntry(clientMessageId);
  }

  async deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    return await this.storage.deleteExpiredSendLog(maxAgeMs);
  }

  async clearSendLog(): Promise<number> {
    return await this.storage.clearSendLog();
  }

  async storeResendJob(job: SendLogResendJob): Promise<void> {
    await this.storage.storeResendJob(job);
  }

  async getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    return await this.storage.getResendJob(jobId);
  }

  async getPendingResendJobs(): Promise<SendLogResendJob[]> {
    return await this.storage.getPendingResendJobs();
  }

  async completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    await this.storage.completeResendJob(jobId, state);
  }

  // ============================================================================
  // Key Recovery Methods (Bug #7 - Identifier Collision Recovery)
  // ============================================================================

  /**
   * Get the maximum EC signed prekey ID in storage.
   * Used to generate new keyIds that will not collide with existing ones.
   *
   * @returns The highest EC signed prekey ID, or 0 if none exist
   */
  async getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    return await this.storage.getEcSignedPreKeyMaxId(identityType);
  }

  /**
   * Get the maximum Kyber prekey ID in storage.
   * Used to generate new keyIds that will not collide with existing ones.
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
  async deleteAllPreKeys(
    identityType?: IdentityType
  ): Promise<{
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

/**
 * Device is stale if:
 * 1. No active session AND no archived sessions, AND age > maxLatency, or
 * 2. Its removal is older than maxLatency
 */
function isStaleDeviceRecord(record: DeviceRecord, now: number, maxLatency: number): boolean {
  const hasNoSessions =
    !record.session?.currentSession &&
    Object.keys(record.session?.archivedSessions ?? {}).length === 0;
  return (
    (hasNoSessions && now - record.createdAt > maxLatency) ||
    isExpiredRemovedDevice(record, now, maxLatency)
  );
}

/** A session is expired when its age exceeds maxRecv. */
function isExpiredSession(record: SessionRecord, now: number, maxRecv: number): boolean {
  const createdAt = record.metadata?.createdAt ?? now;
  return now - createdAt > maxRecv;
}

/**
 * Convert the legacy received content rows of a store that a platform entry
 * opened, then return the store. A row that does not parse is reported as an
 * error through the logger of the store. A failure closes the database, so
 * the failed open holds no file.
 */
export async function convertSqliteLegacyReceivedContent<Store extends SqliteSignalProtocolStore>(
  store: Store,
  database: SqliteRootExecutor
): Promise<Store> {
  // The logger is protected. The store routes its other diagnostics through
  // it, and setLogger can replace it, so the report reads it at the call.
  const reportUnreadable = (legacyKey: string) =>
    (store as unknown as { logger: Required<Logger> }).logger.error(
      LEGACY_RECEIVED_CONTENT_UNREADABLE,
      { legacyKey }
    );
  try {
    await convertLegacyReceivedContent(
      store,
      legacyReceivedContentSource(database),
      reportUnreadable
    );
  } catch (error) {
    await database.close().catch(() => undefined);
    throw error;
  }
  return store;
}
