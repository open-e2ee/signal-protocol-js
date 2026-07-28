/**
 * Node.js Storage Adapter
 *
 * Storage adapter for Node.js applications (CLI tools, servers, etc.)
 * Uses:
 * - Encrypted filesystem for key storage
 * - node:crypto for encryption
 * - Secure file permissions (0600)
 *
 * @example Usage
 * ```typescript
 * const storage = new NodeSignalProtocolStore({
 *   dataDir: '~/.signal-protocol/signal'
 * });
 * await storage.initialize();
 *
 * // Store identity key
 * await storage.storeIdentityKey(keyPair);
 * ```
 */

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
import {
  assertCurrentSessionRecord,
  type SessionRecord,
} from '../../../types/session';
import { ProtocolAddress } from '../../../types/address';
import { IdentityKeyChange, TrustDirection } from '../../../types/trust';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import { getNodeEncryptedDatabase } from './database';
import type { NodeEncryptedDatabase, NodeSenderKeyTree } from './database';
import type { MessageRecord, SessionTrustCommit, UserRecord, DeviceRecord } from '../../../types';
import type { ISignalProtocolLocalStore, SkippedSenderMessageKey } from '../../../types/api';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import { encodeCompositeIdentityV1, UNPINNED_DEVICE_IDENTITY_KEY } from '../../../keys/identity';
import { deserializeSessionRecord, serializeSessionRecord } from '../session-codec';

/**
 * SESAME records as they are persisted.
 *
 * The encrypted state file is JSON, which carries neither `Map` nor
 * `Uint8Array`, so the device map becomes entry pairs and the identity key
 * becomes a byte array. Nested sessions reuse the shared session codec so a
 * device's ratchet state is encoded exactly once, in one format.
 */
interface SerializedNodeDeviceRecord extends Omit<DeviceRecord, 'identityKey' | 'session'> {
  identityKey: number[];
  session: string | null;
}

interface SerializedNodeUserRecord extends Omit<UserRecord, 'devices'> {
  devices: Array<[number, SerializedNodeDeviceRecord]>;
}

function serializeDeviceRecord(record: DeviceRecord): SerializedNodeDeviceRecord {
  return {
    ...record,
    identityKey: Array.from(record.identityKey),
    session: record.session ? serializeSessionRecord(record.session) : null,
  };
}

function deserializeDeviceRecord(data: SerializedNodeDeviceRecord): DeviceRecord {
  return {
    ...data,
    identityKey: Uint8Array.from(data.identityKey),
    session: data.session ? deserializeSessionRecord(data.session) : null,
  };
}

function serializeUserRecord(record: UserRecord): SerializedNodeUserRecord {
  return {
    ...record,
    devices: Array.from(record.devices.entries(), ([deviceId, device]) => [
      deviceId,
      serializeDeviceRecord(device),
    ]),
  };
}

function deserializeUserRecord(data: SerializedNodeUserRecord): UserRecord {
  return {
    ...data,
    devices: new Map(
      data.devices.map(([deviceId, device]) => [deviceId, deserializeDeviceRecord(device)])
    ),
  };
}

/**
 * Decode a persisted device session, treating an unreadable one as absent.
 *
 * `getSessionRecord` already drops a session it cannot decode instead of
 * failing the caller. A maintenance sweep that threw on the same record would
 * abort the whole pass, leaving a store that can never expire anything again.
 */
function readStoredSession(serialized: string | null): SessionRecord | null {
  if (!serialized) return null;
  try {
    return deserializeSessionRecord(serialized);
  } catch {
    return null;
  }
}

/** Read a nested dictionary level, creating it on demand for writes. */
function branch<T>(parent: Record<string, T>, key: string, create: () => T): T {
  const existing = parent[key];
  if (existing !== undefined) return existing;
  const created = create();
  parent[key] = created;
  return created;
}

/** Same, for a level whose value is itself a dictionary. */
function subtree<T extends object>(parent: Record<string, T>, key: string): T {
  return branch(parent, key, () => Object.create(null) as T);
}

/** Remove one device from a group/user/device tree, pruning levels left empty. */
function pruneSenderKeyDevice<T>(
  tree: NodeSenderKeyTree<T>,
  groupId: string,
  userId: string,
  deviceId: number
): void {
  const users = tree[groupId];
  const devices = users?.[userId];
  if (!users || !devices) return;
  delete devices[String(deviceId)];
  if (Object.keys(devices).length === 0) delete users[userId];
  if (Object.keys(users).length === 0) delete tree[groupId];
}

/**
 * Node.js storage adapter configuration
 */
export {};
export interface NodeSignalProtocolStoreConfig {
  dataDir?: string;
}

/**
 * Node.js Storage Adapter
 *
 * Provides encrypted filesystem storage for Signal Protocol keys.
 */
export class NodeSignalProtocolStore implements ISignalProtocolLocalStore {
  private db: NodeEncryptedDatabase;

  constructor(config?: NodeSignalProtocolStoreConfig) {
    this.db = getNodeEncryptedDatabase(config?.dataDir);
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  async initialize(): Promise<void> {
    await this.db.initialize();
  }

  // ============================================================================
  // Identity Key Management (Own Keys)
  // ============================================================================

  async storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.storeIdentityKey(keyPair, it);
  }

  async getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null> {
    const it = identityType ?? 'aci';
    return await this.db.getIdentityKey<IdentityKeyPair>(it);
  }

  async hasIdentityKey(identityType?: IdentityType): Promise<boolean> {
    const key = await this.getIdentityKey(identityType);
    return key !== null;
  }

  async getLocalRegistrationId(identityType?: IdentityType): Promise<number> {
    return await this.db.getRegistrationId(identityType ?? 'aci');
  }

  async setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void> {
    // A registration ID identifies this install for the lifetime of the
    // install. Holding it in memory would hand every restart a fresh one and
    // make every peer read the process as a reinstall.
    await this.db.setRegistrationId(identityType ?? 'aci', id);
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
    const existing = await this.db.getContactIdentity<ContactIdentityRecord>(key);
    const status = evaluateContactIdentityCandidate(existing, identity, suppliedCommitment);
    if (status === 'NEW') {
      await this.db.storeContactIdentity(
        key,
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
    const record = await this.db.getContactIdentity<ContactIdentityRecord>(
      this.getContactIdentityKey(address, identityType)
    );
    if (record) validateContactIdentityRecord(record);
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
    const key = this.getContactIdentityKey(address, identityType);
    return await this.db.mutateContactIdentityAndDeleteSessions<ContactIdentityRecord>(
      key,
      address.userId,
      (existing) => {
        if (!existing) throw new Error('Cannot rotate an unseen identity');
        return acceptRotation(existing, identity, Date.now(), suppliedCommitment);
      }
    );
  }

  async verifyContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    const key = this.getContactIdentityKey(address, identityType);
    return await this.db.mutateContactIdentity<ContactIdentityRecord>(key, (existing) => {
      if (!existing) throw new Error('Cannot verify an unseen identity');
      return verifyContactIdentityRecord(existing, identity, Date.now(), suppliedCommitment);
    });
  }

  async isTrustedIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    _direction: TrustDirection,
    identityType?: IdentityType
  ): Promise<boolean> {
    const saved = await this.getContactIdentity(address, identityType);
    const status = evaluateContactIdentityCandidate(saved, identity);
    return status === 'NEW' || status === 'MATCH';
  }

  // ============================================================================
  // PreKey Management
  // ============================================================================

  async storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.storeEcSignedPreKey(signedPreKey, it);
  }

  async getEcSignedPreKey(
    keyId?: number,
    identityType?: IdentityType
  ): Promise<EcSignedPreKey | null> {
    const it = identityType ?? 'aci';
    return await this.db.getEcSignedPreKey<EcSignedPreKey>(keyId, it);
  }

  async getAllEcSignedPreKeys(identityType?: IdentityType): Promise<EcSignedPreKey[]> {
    const it = identityType ?? 'aci';
    return await this.db.getAllEcSignedPreKeys<EcSignedPreKey>(it);
  }

  async removeEcSignedPreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    return await this.db.removeEcSignedPreKey<EcSignedPreKey>(keyId, it);
  }

  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.storeEcOneTimePreKeys(prekeys, it);
  }

  async getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]> {
    const it = identityType ?? 'aci';
    return await this.db.getEcOneTimePreKeys<EcOneTimePreKey>(it);
  }

  async removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.removeEcOneTimePreKey<EcOneTimePreKey>((key) => key.keyId === preKeyId, it);
  }

  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType?: IdentityType
  ): Promise<void> {
    await this.db.storeKemOneTimePreKeys(prekeys, identityType ?? 'aci');
  }

  async getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]> {
    return await this.db.getKemOneTimePreKeys<KemOneTimePreKey>(identityType ?? 'aci');
  }

  async getKemOneTimePreKey(
    keyId: number,
    identityType?: IdentityType
  ): Promise<KemOneTimePreKey | null> {
    return (await this.getKemOneTimePreKeys(identityType)).find((key) => key.keyId === keyId) ?? null;
  }

  async removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void> {
    await this.db.removeKemOneTimePreKey<KemOneTimePreKey>(keyId, identityType ?? 'aci');
  }

  async getKemOneTimePreKeyCount(identityType?: IdentityType): Promise<number> {
    return (await this.getKemOneTimePreKeys(identityType)).length;
  }

  async storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.storeKyberPreKey(kyberPreKey.keyId, kyberPreKey, it);
  }

  async getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null> {
    const it = identityType ?? 'aci';
    // Always use ID 1 for Kyber prekey (following PQXDH spec)
    return await this.db.getKyberPreKey<KyberPreKey>(1, it);
  }

  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void> {
    const it = identityType ?? 'aci';
    await this.db.markKyberPreKeyUsed(`${it}:${kyberPreKeyId}`, {
      signedPreKeyId,
      baseKeyBytes: Array.from(baseKeyBytes),
    });
  }

  // ============================================================================
  // Session Management
  // ============================================================================

  async storeSessionRecord(address: ProtocolAddress, record: SessionRecord): Promise<void> {
    assertCurrentSessionRecord(record);
    const key = this.getAddressKey(address);
    await this.db.storeSession(key, address.userId, address.deviceId, serializeSessionRecord(record));
  }

  async getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null> {
    const key = this.getAddressKey(address);
    const serialized = await this.db.getSession(key);
    if (serialized) {
      try {
        const record = deserializeSessionRecord(serialized);
        assertCurrentSessionRecord(record);
        return record;
      } catch {
        await this.db.deleteSession(key);
        return null;
      }
    }
    return null;
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    const key = this.getAddressKey(address);
    await this.db.deleteSession(key);
  }

  async archiveCurrentSession(
    address: ProtocolAddress,
    newSession?: SessionState | null
  ): Promise<void> {
    const key = this.getAddressKey(address);
    const serialized = await this.db.getSession(key);
    const record = serialized ? deserializeSessionRecord(serialized) : null;

    if (!record) {
      return;
    }

    // Archive current session by its baseKey
    if (record.currentSession) {
      if (!record.archivedSessions) {
        record.archivedSessions = {};
      }
      record.archivedSessions[record.currentSession.baseKey] = record.currentSession;
    }

    // Set new session as current
    record.currentSession = newSession || null;
    await this.db.storeSession(key, address.userId, address.deviceId, serializeSessionRecord(record));
  }

  async getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    const serialized = await this.db.getSessionsForUser(userId);
    return serialized.map(deserializeSessionRecord);
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    assertCurrentSessionRecord(commit.record);
    const contactKey = this.getContactIdentityKey(
      commit.address,
      commit.contactIdentityType
    );
    await this.db.commitSessionTrust(
      this.getAddressKey(commit.address),
      commit.address.userId,
      commit.address.deviceId,
      serializeSessionRecord(commit.record),
      commit.localIdentityType,
      contactKey,
      (existing: ContactIdentityRecord | null): ContactIdentityRecord => {
        const status = evaluateContactIdentityCandidate(existing, commit.contactIdentity);
        if (status === 'NEW') {
          return createUnverifiedContactIdentityRecord(commit.contactIdentity, Date.now());
        }
        if (status === 'MATCH' && existing) return existing;
        throw new Error(`Atomic session/trust commit rejected contact identity status ${status}`);
      },
      commit.oneTimePreKeyId,
      commit.kemOneTimePreKeyId
    );
  }

  async hasSession(address: ProtocolAddress): Promise<boolean> {
    const record = await this.getSessionRecord(address);
    return record !== null;
  }

  async getSessionCount(): Promise<number> {
    const stats = await this.db.getStats();
    return stats.sessions;
  }

  // ============================================================================
  // Database Encryption
  // ============================================================================

  async getDatabaseKey(): Promise<Uint8Array> {
    const key = await this.db['dbKey'];
    if (!key) {
      throw new EncryptionError(
        'Database key not initialized',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    return key;
  }

  // ============================================================================
  // SESAME Multi-Device Session Management
  //
  // A device's session is the same session the protocol store holds for that
  // address. Writes go to both so `getSessionRecord` and `getDeviceSession`
  // never disagree about which ratchet is current.
  // ============================================================================

  async getUserRecord(userId: string): Promise<UserRecord | null> {
    const { users } = await this.db.readSesameState<SerializedNodeUserRecord>();
    const stored = users[userId];
    return stored ? deserializeUserRecord(stored) : null;
  }

  async setUserRecord(userId: string, record: UserRecord): Promise<void> {
    const serialized = serializeUserRecord(record);
    await this.db.mutateSesameState<SerializedNodeUserRecord, void>(({ users, sessions }) => {
      users[userId] = serialized;
      for (const [deviceId, device] of serialized.devices) {
        if (!device.session) continue;
        sessions[this.getAddressKey({ userId, deviceId })] = {
          userId,
          deviceId,
          serializedRecord: device.session,
        };
      }
    });
  }

  async getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null> {
    // The live session is read through `getSessionRecord` rather than out of the
    // device record, so a session this store would refuse to hand the protocol
    // layer is not handed to the SESAME layer either.
    const session = await this.getSessionRecord(ProtocolAddress.create(userId, deviceId));
    const { users } = await this.db.readSesameState<SerializedNodeUserRecord>();
    const stored = users[userId]?.devices.find(([id]) => id === deviceId)?.[1] ?? null;

    if (!session) return stored ? deserializeDeviceRecord(stored) : null;

    const now = Date.now();
    return {
      ...(stored ? deserializeDeviceRecord(stored) : {}),
      userId,
      deviceId,
      // The identity pin is a trust decision, so it comes from what was
      // persisted rather than from whichever session happens to be current.
      // Re-deriving it would unpin a device the moment its session is archived.
      identityKey: stored?.identityKey.length
        ? Uint8Array.from(stored.identityKey)
        : session.currentSession?.remoteIdentity
          ? encodeCompositeIdentityV1(session.currentSession.remoteIdentity)
          : UNPINNED_DEVICE_IDENTITY_KEY,
      session,
      createdAt: session.metadata?.createdAt ?? stored?.createdAt ?? now,
      updatedAt: now,
    };
  }

  async setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void> {
    const serialized = serializeDeviceRecord(record);
    await this.db.mutateSesameState<SerializedNodeUserRecord, void>(({ users, sessions }) => {
      const now = Date.now();
      const user = branch(users, userId, () => ({
        userId,
        devices: [],
        createdAt: now,
        updatedAt: now,
      }));
      const index = user.devices.findIndex(([id]) => id === deviceId);
      if (index >= 0) user.devices[index] = [deviceId, serialized];
      else user.devices.push([deviceId, serialized]);
      user.updatedAt = now;

      if (serialized.session) {
        sessions[this.getAddressKey({ userId, deviceId })] = {
          userId,
          deviceId,
          serializedRecord: serialized.session,
        };
      }
    });
  }

  async deleteDeviceRecord(userId: string, deviceId: number): Promise<void> {
    await this.db.mutateSesameState<SerializedNodeUserRecord, void>(({ users, sessions }) => {
      delete sessions[this.getAddressKey({ userId, deviceId })];
      const user = users[userId];
      if (!user) return;
      user.devices = user.devices.filter(([id]) => id !== deviceId);
      user.updatedAt = Date.now();
      if (user.devices.length === 0) delete users[userId];
    });
  }

  async getDeviceSession(userId: string, deviceId: number): Promise<SessionRecord | null> {
    return (await this.getDeviceRecord(userId, deviceId))?.session ?? null;
  }

  async setDeviceSession(userId: string, deviceId: number, session: SessionRecord): Promise<void> {
    const record = await this.getDeviceRecord(userId, deviceId);
    if (!record) throw new Error(`Device record not found: ${userId}:${deviceId}`);
    record.session = session;
    record.updatedAt = Date.now();
    await this.setDeviceRecord(userId, deviceId, record);
  }

  async deleteStaleRecords(maxLatency: number): Promise<number> {
    return await this.db.mutateSesameState<SerializedNodeUserRecord, number>(({ users }) => {
      const now = Date.now();
      let deleted = 0;

      for (const userId of Object.keys(users)) {
        const user = users[userId];
        const kept = user.devices.filter(([, device]) => {
          const record = readStoredSession(device.session);
          const hasNoSessions =
            !record ||
            (!record.currentSession && Object.keys(record.archivedSessions).length === 0);
          return !(hasNoSessions && now - device.createdAt > maxLatency);
        });

        deleted += user.devices.length - kept.length;
        user.devices = kept;
        user.updatedAt = now;
        if (user.devices.length === 0) delete users[userId];
      }

      return deleted;
    });
  }

  async cleanupExpiredSessions(maxRecv: number): Promise<number> {
    return await this.db.mutateSesameState<SerializedNodeUserRecord, number>(
      ({ users, sessions }) => {
        const now = Date.now();
        let deleted = 0;

        for (const user of Object.values(users)) {
          for (const [deviceId, device] of user.devices) {
            if (!device.session) continue;
            const record = readStoredSession(device.session);
            if (!record) {
              device.session = null;
              delete sessions[this.getAddressKey({ userId: user.userId, deviceId })];
              continue;
            }
            const createdAt = record.metadata?.createdAt ?? 0;

            if (now - createdAt > maxRecv) {
              if (record.currentSession) deleted++;
              deleted += Object.keys(record.archivedSessions).length;
              device.session = null;
              delete sessions[this.getAddressKey({ userId: user.userId, deviceId })];
            } else {
              for (const [baseKey, state] of Object.entries(record.archivedSessions)) {
                if (now - (state?.lastUsedAt ?? createdAt) <= maxRecv) continue;
                delete record.archivedSessions[baseKey as keyof typeof record.archivedSessions];
                deleted++;
              }
              device.session = serializeSessionRecord(record);
              sessions[this.getAddressKey({ userId: user.userId, deviceId })] = {
                userId: user.userId,
                deviceId,
                serializedRecord: device.session,
              };
            }
            device.updatedAt = now;
          }
          user.updatedAt = now;
        }

        return deleted;
      }
    );
  }

  async getAllUserIds(): Promise<string[]> {
    const { users } = await this.db.readSesameState<SerializedNodeUserRecord>();
    return Object.keys(users);
  }

  async getSesameDeviceIds(userId: string): Promise<number[]> {
    const { users } = await this.db.readSesameState<SerializedNodeUserRecord>();
    return users[userId]?.devices.map(([deviceId]) => deviceId) ?? [];
  }

  // ============================================================================
  // Sender Keys (Group Messaging)
  // ============================================================================

  async storeSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    state: SenderKeyState
  ): Promise<void> {
    await this.db.mutateSenderKeyState<SenderKeyState, void>(({ current }) => {
      const users = subtree(current, groupId);
      subtree(users, userId)[String(deviceId)] = state;
    });
  }

  async getSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null> {
    const { current } = await this.db.readSenderKeyState<SenderKeyState>();
    return current[groupId]?.[userId]?.[String(deviceId)] ?? null;
  }

  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    await this.db.mutateSenderKeyState<SenderKeyState, void>(({ current, records }) => {
      pruneSenderKeyDevice(current, groupId, userId, deviceId);
      pruneSenderKeyDevice(records, groupId, userId, deviceId);
    });
  }

  async resolveGroupForSenderKeyId(
    senderKeyId: string,
    userId: string,
    deviceId: number
  ): Promise<string | null> {
    if (!senderKeyId) return null;
    const { current, records } = await this.db.readSenderKeyState<SenderKeyState>();
    const device = String(deviceId);

    for (const groupId of new Set([...Object.keys(current), ...Object.keys(records)])) {
      if (current[groupId]?.[userId]?.[device]?.senderKeyId === senderKeyId) return groupId;
      // A message encrypted just before a rotation still names the superseded
      // key, so the retained previous states have to be searched too.
      const retained = records[groupId]?.[userId]?.[device];
      if (retained?.some((state) => state.senderKeyId === senderKeyId)) return groupId;
    }

    return null;
  }

  async getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]> {
    const { current } = await this.db.readSenderKeyState<SenderKeyState>();
    const users = current[groupId];
    if (!users) return [];
    return Object.values(users).flatMap((devices) => Object.values(devices));
  }

  async deleteAllSenderKeysForGroup(groupId: string): Promise<number> {
    return await this.db.mutateSenderKeyState<SenderKeyState, number>(
      ({ current, records, skipped }) => {
        const users = current[groupId];
        const count = users
          ? Object.values(users).reduce((total, devices) => total + Object.keys(devices).length, 0)
          : 0;
        // Each identifier is its own key, so deleting one group cannot reach a
        // group whose name merely shares a prefix with it.
        delete current[groupId];
        delete records[groupId];
        delete skipped[groupId];
        return count;
      }
    );
  }

  async storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void> {
    if (states.length === 0) return;
    await this.db.mutateSenderKeyState<SenderKeyState, void>(({ current, records }) => {
      const device = String(deviceId);
      subtree(subtree(current, groupId), userId)[device] = states[0];
      subtree(subtree(records, groupId), userId)[device] = states;
    });
  }

  async getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    const { current, records } = await this.db.readSenderKeyState<SenderKeyState>();
    const device = String(deviceId);
    const record = records[groupId]?.[userId]?.[device];
    if (record) return record;

    const state = current[groupId]?.[userId]?.[device];
    return state ? [state] : null;
  }

  // ============================================================================
  // Skipped Sender Keys (Out-of-Order Group Messages)
  // ============================================================================

  async storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void> {
    await this.db.mutateSenderKeyState<SenderKeyState, void>(({ skipped }) => {
      const senders = subtree(skipped, groupId);
      const devices = subtree(senders, senderId);
      subtree(devices, String(senderDeviceId))[String(chainIndex)] = messageKey;
    });
  }

  async getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null> {
    const { skipped } = await this.db.readSenderKeyState<SenderKeyState>();
    const stored =
      skipped[groupId]?.[senderId]?.[String(senderDeviceId)]?.[String(chainIndex)];
    return (stored as SkippedSenderMessageKey | undefined) ?? null;
  }

  async deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void> {
    await this.db.mutateSenderKeyState<SenderKeyState, void>(({ skipped }) => {
      const keys = skipped[groupId]?.[senderId]?.[String(senderDeviceId)];
      if (keys) delete keys[String(chainIndex)];
    });
  }

  async countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number> {
    const { skipped } = await this.db.readSenderKeyState<SenderKeyState>();
    const keys = skipped[groupId]?.[senderId]?.[String(senderDeviceId)];
    return keys ? Object.keys(keys).length : 0;
  }

  async deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number> {
    return await this.db.mutateSenderKeyState<SenderKeyState, number>(({ skipped }) => {
      const keys = skipped[groupId]?.[senderId]?.[String(senderDeviceId)];
      if (!keys) return 0;
      // Chain index is the message order, so the lowest indices are the oldest.
      const oldest = Object.keys(keys)
        .sort((a, b) => Number(a) - Number(b))
        .slice(0, count);
      for (const chainIndex of oldest) delete keys[chainIndex];
      return oldest.length;
    });
  }

  // ============================================================================
  // Message Records (SESAME Retry Support)
  // ============================================================================

  async storeMessageRecord(record: MessageRecord): Promise<void> {
    await this.db.mutateMessageRecords<MessageRecord, void>((records) => {
      subtree(records, record.sessionId)[String(record.timestamp)] = record;
    });
  }

  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    const records = await this.db.readMessageRecords<MessageRecord>();
    return records[sessionId]?.[String(timestamp)] ?? null;
  }

  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    await this.db.mutateMessageRecords<MessageRecord, void>((records) => {
      const session = records[sessionId];
      if (!session) return;
      delete session[String(timestamp)];
      if (Object.keys(session).length === 0) delete records[sessionId];
    });
  }

  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    const cutoff = Date.now() - maxAgeMs;
    return await this.db.mutateMessageRecords<MessageRecord, number>((records) => {
      let deleted = 0;
      for (const sessionId of Object.keys(records)) {
        const session = records[sessionId];
        for (const key of Object.keys(session)) {
          if (session[key].createdAt >= cutoff) continue;
          delete session[key];
          deleted++;
        }
        if (Object.keys(session).length === 0) delete records[sessionId];
      }
      return deleted;
    });
  }

  async clearAllMessageRecords(): Promise<number> {
    return await this.db.mutateMessageRecords<MessageRecord, number>((records) => {
      let deleted = 0;
      for (const sessionId of Object.keys(records)) {
        deleted += Object.keys(records[sessionId]).length;
        delete records[sessionId];
      }
      return deleted;
    });
  }

  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    return await this.db.mutateMessageRecords<MessageRecord, number>((records) => {
      const deleted = Object.keys(records[sessionId] ?? {}).length;
      delete records[sessionId];
      return deleted;
    });
  }

  // ============================================================================
  // Metadata
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    return await this.db.getMetadataValue(key);
  }

  async setMetadata(key: string, value: string): Promise<void> {
    await this.db.setMetadataValue(key, value);
  }

  // ============================================================================
  // Key Recovery (PQXDH §4.13 identifier-collision recovery)
  // ============================================================================

  async getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    return await this.db.getEcSignedPreKeyMaxId(identityType ?? 'aci');
  }

  async getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number> {
    return await this.db.getKyberPreKeyMaxId(identityType ?? 'aci');
  }

  async deleteAllPreKeys(identityType?: IdentityType): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }> {
    return await this.db.deleteAllPreKeys(identityType ?? 'aci');
  }

  async clearAllSessions(): Promise<void> {
    // A device record whose session is gone is not a device this store can
    // reach, so the SESAME records go with the sessions in the same commit.
    await this.db.clearSesameState();
  }

  async getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    return await this.db.getDetailedStats();
  }

  // ============================================================================
  // Utility
  // ============================================================================

  async clearAllKeys(): Promise<void> {
    await this.db.deleteDatabase();
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private getAddressKey(address: ProtocolAddress): string {
    return ProtocolAddress.toString(address);
  }

  private getContactIdentityKey(address: ProtocolAddress, identityType?: IdentityType): string {
    return `${address.userId}:${identityType ?? 'aci'}`;
  }
}
