/**
 * Key storage over one SQLite executor.
 *
 * Every operation lives in the module that owns its concept. This class binds
 * them to one executor and logger and keeps the key storage surface that the
 * store and the tests call.
 */

import type {
  CompositeIdentityV1,
  ContactIdentityRecord,
  EcOneTimePreKey,
  EcSignedPreKey,
  IdentityKeyPair,
  IdentityType,
  KemOneTimePreKey,
  KyberPreKey,
} from '../../../../keys';
import type {
  MessageRecord,
  NewSendLogPayload,
  ReceiveWorkMetadataWrite,
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  ReceiveWorkUsage,
  RetainedKyberPreKey,
  SessionState,
  SendLogDevice,
  SendLogEntry,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
  SessionTrustCommit,
} from '../../../../types';
import { ProtocolAddress } from '../../../../types/address';
import type { SessionRecord } from '../../../../types/session';
import type { IdentityKeyChange } from '../../../../types/trust';
import { resolveSignalProtocolLogger, type Logger } from '../../../../logger';
import type { SqliteExecutor } from '../driver';
import * as account from './account';
import * as contacts from './contact-identities';
import type { KeyStorageContext } from './context';
import * as identity from './identity-keys';
import * as messageRecords from './message-records';
import * as metadata from './metadata';
import * as oneTime from './one-time-prekeys';
import * as receiveWork from './receive-work';
import * as sendLog from './send-log';
import * as sessions from './sessions';
import { commitSessionTrust } from './session-trust';
import * as signed from './signed-prekeys';

export type { DetailedStats, DeletedPreKeyCounts } from './account';

export interface SqliteKeyStorageOptions {
  logger?: Logger;
}

type PeerAddress = { userId: string; deviceId: number };

export class SqliteKeyStorage {
  private readonly context: KeyStorageContext;

  constructor(db: SqliteExecutor, options: SqliteKeyStorageOptions = {}) {
    this.context = { db, logger: resolveSignalProtocolLogger(options.logger) };
  }

  /** The executor that every operation of this storage uses. */
  get db(): SqliteExecutor {
    return this.context.db;
  }

  setLogger(providedLogger?: Logger): void {
    this.context.logger = resolveSignalProtocolLogger(providedLogger);
  }

  // Identity keys and registration IDs

  storeIdentityKey(keyPair: IdentityKeyPair, identityType: IdentityType = 'aci'): Promise<void> {
    return identity.storeIdentityKey(this.context, keyPair, identityType);
  }

  getIdentityKey(identityType: IdentityType = 'aci'): Promise<IdentityKeyPair | null> {
    return identity.getIdentityKey(this.context, identityType);
  }

  deleteIdentityKey(identityType: IdentityType = 'aci'): Promise<void> {
    return identity.deleteIdentityKey(this.context, identityType);
  }

  hasIdentityKey(identityType: IdentityType = 'aci'): Promise<boolean> {
    return identity.hasIdentityKey(this.context, identityType);
  }

  getLocalRegistrationId(identityType: IdentityType = 'aci'): Promise<number> {
    return identity.getLocalRegistrationId(this.context, identityType);
  }

  setLocalRegistrationId(id: number, identityType: IdentityType = 'aci'): Promise<void> {
    return identity.setLocalRegistrationId(this.context, id, identityType);
  }

  // Signed prekeys

  storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    return signed.storeEcSignedPreKey(this.context, signedPreKey, identityType);
  }

  getEcSignedPreKey(
    keyId?: number,
    identityType: IdentityType = 'aci'
  ): Promise<EcSignedPreKey | null> {
    return signed.getEcSignedPreKey(this.context, keyId, identityType);
  }

  getAllEcSignedPreKeys(identityType: IdentityType = 'aci'): Promise<EcSignedPreKey[]> {
    return signed.getAllEcSignedPreKeys(this.context, identityType);
  }

  removeEcSignedPreKey(keyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    return signed.removeEcSignedPreKey(this.context, keyId, identityType);
  }

  storeKyberPreKey(kyberPreKey: KyberPreKey, identityType: IdentityType = 'aci'): Promise<void> {
    return signed.storeKyberPreKey(this.context, kyberPreKey, identityType);
  }

  getKyberPreKey(identityType: IdentityType = 'aci'): Promise<{
    keyId: number;
    publicKey: string;
    privateKey: string;
    signature: string;
    timestamp: number;
  } | null> {
    return signed.getKyberPreKey(this.context, identityType);
  }

  getKyberPreKeyById(
    keyId: number,
    identityType: IdentityType = 'aci'
  ): Promise<RetainedKyberPreKey | null> {
    return signed.getKyberPreKeyById(this.context, keyId, identityType);
  }

  markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    return signed.markKyberPreKeyUsed(
      this.context,
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes,
      identityType
    );
  }

  deleteKyberPreKey(id: number, identityType: IdentityType = 'aci'): Promise<void> {
    return signed.deleteKyberPreKey(this.context, id, identityType);
  }

  getEcSignedPreKeyMaxId(identityType: IdentityType = 'aci'): Promise<number> {
    return signed.getEcSignedPreKeyMaxId(this.context, identityType);
  }

  getKyberPreKeyMaxId(identityType: IdentityType = 'aci'): Promise<number> {
    return signed.getKyberPreKeyMaxId(this.context, identityType);
  }

  // One-time prekeys

  storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    return oneTime.storeEcOneTimePreKeys(this.context, prekeys, identityType);
  }

  getEcOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<EcOneTimePreKey[]> {
    return oneTime.getEcOneTimePreKeys(this.context, identityType);
  }

  removeEcOneTimePreKey(preKeyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    return oneTime.removeEcOneTimePreKey(this.context, preKeyId, identityType);
  }

  getEcOneTimePreKeyCount(identityType: IdentityType = 'aci'): Promise<number> {
    return oneTime.getEcOneTimePreKeyCount(this.context, identityType);
  }

  storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    return oneTime.storeKemOneTimePreKeys(this.context, prekeys, identityType);
  }

  getKemOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<KemOneTimePreKey[]> {
    return oneTime.getKemOneTimePreKeys(this.context, identityType);
  }

  getKemOneTimePreKey(
    keyId: number,
    identityType: IdentityType = 'aci'
  ): Promise<KemOneTimePreKey | null> {
    return oneTime.getKemOneTimePreKey(this.context, keyId, identityType);
  }

  removeKemOneTimePreKey(keyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    return oneTime.removeKemOneTimePreKey(this.context, keyId, identityType);
  }

  getKemOneTimePreKeyCount(identityType: IdentityType = 'aci'): Promise<number> {
    return oneTime.getKemOneTimePreKeyCount(this.context, identityType);
  }

  // Sessions

  storeSession(sessionId: string, session: SessionState | SessionRecord): Promise<void> {
    return sessions.storeSession(this.context, sessionId, session);
  }

  getSession(sessionId: string): Promise<SessionState | null> {
    return sessions.getSession(this.context, sessionId);
  }

  deleteSession(sessionId: string): Promise<void> {
    return sessions.deleteSession(this.context, sessionId);
  }

  clearAllSessions(): Promise<void> {
    return sessions.clearAllSessions(this.context);
  }

  getAllSessionIds(): Promise<string[]> {
    return sessions.getAllSessionIds(this.context);
  }

  getSessionIdsForUser(userId: string): Promise<string[]> {
    return sessions.getSessionIdsForUser(this.context, userId);
  }

  getAllSessions(sessionIds: string[]): Promise<Record<string, SessionState>> {
    return sessions.getAllSessions(this.context, sessionIds);
  }

  validateSession(sessionId: string): Promise<boolean> {
    return sessions.validateSession(this.context, sessionId);
  }

  storeSessionRecord(address: PeerAddress, record: SessionRecord): Promise<void> {
    return sessions.storeSessionRecord(this.context, address, record);
  }

  commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    return commitSessionTrust(this.context, commit);
  }

  getSessionRecord(address: PeerAddress): Promise<SessionRecord | null> {
    return sessions.getSessionRecord(this.context, address);
  }

  deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    return sessions.deleteSessionRecord(this.context, address);
  }

  archiveCurrentSession(address: ProtocolAddress, newSession?: SessionState): Promise<void> {
    return sessions.archiveCurrentSession(this.context, address, newSession);
  }

  getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    return sessions.getSessionsForUser(this.context, userId);
  }

  hasSession(address: PeerAddress): Promise<boolean> {
    return sessions.hasSession(this.context, address);
  }

  getSessionCount(): Promise<number> {
    return sessions.getSessionCount(this.context);
  }

  // Metadata

  getMetadata(key: string): Promise<string | null> {
    return metadata.getMetadata(this.context.db, key);
  }

  setMetadata(key: string, value: string): Promise<void> {
    return metadata.setMetadata(this.context.db, key, value);
  }

  deleteMetadata(key: string): Promise<void> {
    return metadata.deleteMetadata(this.context.db, key);
  }

  compareAndSetMetadata(key: string, expected: string | null, value: string | null): Promise<boolean> {
    return metadata.compareAndSetMetadata(this.context.db, key, expected, value);
  }

  // Receive records

  getReceiveWork(workId: string): Promise<ReceiveWorkRecord | null> {
    return receiveWork.getReceiveWork(this.context.db, workId);
  }

  putReceiveWork(record: ReceiveWorkRecord, expectedRevision: number | null): Promise<boolean> {
    return receiveWork.putReceiveWork(this.context.db, record, expectedRevision);
  }

  listReceiveWork(query?: ReceiveWorkQuery): Promise<ReceiveWorkRecord[]> {
    return receiveWork.listReceiveWork(this.context.db, query);
  }

  receiveWorkUsage(query?: { groupId?: string }): Promise<ReceiveWorkUsage> {
    return receiveWork.receiveWorkUsage(this.context.db, query);
  }

  completeReceiveWork(
    workId: string,
    expectedRevision: number,
    metadataWrites?: readonly ReceiveWorkMetadataWrite[]
  ): Promise<boolean> {
    return receiveWork.completeReceiveWork(this.context.db, workId, expectedRevision, metadataWrites);
  }

  // Contact identities

  saveContactIdentity(
    address: PeerAddress,
    identityKey: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<IdentityKeyChange> {
    return contacts.saveContactIdentity(
      this.context,
      address,
      identityKey,
      identityType,
      suppliedCommitment
    );
  }

  getContactIdentity(
    address: PeerAddress,
    identityType: IdentityType = 'aci'
  ): Promise<ContactIdentityRecord | null> {
    return contacts.getContactIdentity(this.context, address, identityType);
  }

  async acceptContactIdentityRotation(
    address: PeerAddress,
    identityKey: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return await this.acceptContactIdentityRotationAndDeleteSessions(
      ProtocolAddress.create(address.userId, address.deviceId),
      identityKey,
      identityType,
      suppliedCommitment
    );
  }

  acceptContactIdentityRotationAndDeleteSessions(
    address: ProtocolAddress,
    identityKey: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return contacts.acceptContactIdentityRotationAndDeleteSessions(
      this.context,
      address,
      identityKey,
      identityType,
      suppliedCommitment
    );
  }

  verifyContactIdentity(
    address: PeerAddress,
    identityKey: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return contacts.verifyContactIdentity(
      this.context,
      address,
      identityKey,
      identityType,
      suppliedCommitment
    );
  }

  isTrustedIdentity(
    address: PeerAddress,
    identityKey: CompositeIdentityV1,
    _direction: number,
    identityType: IdentityType = 'aci'
  ): Promise<boolean> {
    return contacts.isTrustedIdentity(this.context, address, identityKey, identityType);
  }

  // Message records

  storeMessageRecord(record: MessageRecord): Promise<void> {
    return messageRecords.storeMessageRecord(this.context, record);
  }

  getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    return messageRecords.getMessageRecord(this.context, sessionId, timestamp);
  }

  deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    return messageRecords.deleteExpiredMessageRecords(this.context, maxAgeMs);
  }

  clearAllMessageRecords(): Promise<number> {
    return messageRecords.clearAllMessageRecords(this.context);
  }

  deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    return messageRecords.deleteMessageRecordsForSession(this.context, sessionId);
  }

  rewriteMessageRecords(rewrite: (record: MessageRecord) => string | null): Promise<number> {
    return messageRecords.rewriteMessageRecords(this.context, rewrite);
  }

  getMessageRecordCount(): Promise<number> {
    return messageRecords.getMessageRecordCount(this.context);
  }

  deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    return messageRecords.deleteMessageRecord(this.context, sessionId, timestamp);
  }

  // Send log

  storeSendLogEntry(payload: NewSendLogPayload, recipients: readonly SendLogDevice[]): Promise<void> {
    return sendLog.storeSendLogEntry(this.context, payload, recipients);
  }

  appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    return sendLog.appendSendLogRecipients(this.context, clientMessageId, recipients);
  }

  markSendLogComplete(clientMessageId: string): Promise<void> {
    return sendLog.markSendLogComplete(this.context, clientMessageId);
  }

  getSendLogEntry(clientMessageId: string, recipient: SendLogDevice): Promise<SendLogEntry | null> {
    return sendLog.getSendLogEntry(this.context, clientMessageId, recipient);
  }

  findSendLogEntries(recipient: SendLogDevice, clientTimestamp: number): Promise<SendLogEntry[]> {
    return sendLog.findSendLogEntries(this.context, recipient, clientTimestamp);
  }

  getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    return sendLog.getSendLogRecipients(this.context, clientMessageId);
  }

  deleteSendLogRecipient(clientMessageId: string, recipient: SendLogDevice): Promise<boolean> {
    return sendLog.deleteSendLogRecipient(this.context, clientMessageId, recipient);
  }

  deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    return sendLog.deleteSendLogRecipientsByTimestamp(this.context, recipient, clientTimestamps);
  }

  incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    return sendLog.incrementSendLogResendCount(this.context, clientMessageId, recipient);
  }

  deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    return sendLog.deleteSendLogEntry(this.context, clientMessageId);
  }

  deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    return sendLog.deleteExpiredSendLog(this.context, maxAgeMs);
  }

  clearSendLog(): Promise<number> {
    return sendLog.clearSendLog(this.context);
  }

  storeResendJob(job: SendLogResendJob): Promise<void> {
    return sendLog.storeResendJob(this.context, job);
  }

  getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    return sendLog.getResendJob(this.context, jobId);
  }

  getPendingResendJobs(): Promise<SendLogResendJob[]> {
    return sendLog.getPendingResendJobs(this.context);
  }

  completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    return sendLog.completeResendJob(this.context, jobId, state);
  }

  // Account

  clearAllKeys(): Promise<void> {
    return account.clearAllKeys(this.context);
  }

  wipeAllSignalProtocolData(): Promise<account.DetailedStats> {
    return account.wipeAllSignalProtocolData(this.context);
  }

  getStorageStats(): Promise<{
    hasIdentityKey: boolean;
    hasEcSignedPreKey: boolean;
    ecOneTimePreKeysCount: number;
  }> {
    return account.getStorageStats(this.context);
  }

  getDetailedStats(): Promise<account.DetailedStats> {
    return account.getDetailedStats(this.context);
  }

  deleteAllPreKeys(identityType: IdentityType = 'aci'): Promise<account.DeletedPreKeyCounts> {
    return account.deleteAllPreKeys(this.context, identityType);
  }
}
