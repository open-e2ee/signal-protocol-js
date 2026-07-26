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
import type { NodeEncryptedDatabase } from './database';
import type { SessionTrustCommit } from '../../../types';
import { deserializeSessionRecord, serializeSessionRecord } from '../session-codec';

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
export class NodeSignalProtocolStore {
  private db: NodeEncryptedDatabase;
  private registrationIds = new Map<IdentityType, number>();
  private kyberUsage = new Map<string, { signedPreKeyId: number; baseKeyBytes: Uint8Array }>();

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
    this.kyberUsage.set(`${it}:${kyberPreKeyId}`, { signedPreKeyId, baseKeyBytes });
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
  // Utility
  // ============================================================================

  async clearAllKeys(): Promise<void> {
    await this.db.deleteDatabase();
    this.registrationIds.clear();
    this.kyberUsage.clear();
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
