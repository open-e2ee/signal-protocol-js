/**
 * Contact identity trust: the pinned composite identity of each peer, its
 * rotation, and its verification.
 */

import type {
  CompositeIdentityV1,
  ContactIdentityRecord,
  IdentityType,
} from '../../../../keys';
import {
  acceptContactIdentityRotation as acceptRotation,
  createUnverifiedContactIdentityRecord,
  evaluateContactIdentityCandidate,
  validateContactIdentityRecord,
  verifyContactIdentityRecord,
} from '../../../../keys/identity';
import type { IdentityKeyChange as IdentityKeyChangeType } from '../../../../types/trust';
import { ProtocolAddress } from '../../../../types/address';
import type { SqliteExecutor } from '../driver';
import {
  buildContactIdentityId,
  getContactIdentity as modelGetContactIdentity,
  saveContactIdentity as modelSaveContactIdentity,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

type PeerAddress = { userId: string; deviceId: number };

export async function saveContactIdentity(
  ctx: KeyStorageContext,
  address: PeerAddress,
  identity: CompositeIdentityV1,
  identityType: IdentityType,
  suppliedCommitment?: Uint8Array
): Promise<IdentityKeyChangeType> {
  try {
    const { IdentityKeyChange } = await import('../../../../types/trust');
    const existing = await modelGetContactIdentity(ctx.db, address.userId, identityType);
    const status = evaluateContactIdentityCandidate(existing, identity, suppliedCommitment);
    if (status === 'NEW') {
      await modelSaveContactIdentity(
        ctx.db,
        address.userId,
        createUnverifiedContactIdentityRecord(identity, Date.now()),
        identityType
      );
      return IdentityKeyChange.NEW_IDENTITY;
    }
    if (status === 'MATCH') return IdentityKeyChange.UNCHANGED;
    if (status === 'ROLLBACK') return IdentityKeyChange.ROLLBACK;
    return IdentityKeyChange.CHANGED;
  } catch (error) {
    throw keyStorageError('Failed to save contact identity', error);
  }
}

export async function getContactIdentity(
  ctx: KeyStorageContext,
  address: PeerAddress,
  identityType: IdentityType
): Promise<ContactIdentityRecord | null> {
  try {
    return await modelGetContactIdentity(ctx.db, address.userId, identityType);
  } catch (error) {
    throw keyStorageError('Failed to get contact identity', error);
  }
}

/** Read and validate the pinned record, in the caller's transaction. */
async function requirePinnedRecord(
  tx: SqliteExecutor,
  recipientId: string,
  unseenMessage: string
): Promise<ContactIdentityRecord> {
  const row = await tx.first<{ recordJson: string }>(
    'SELECT record_json AS recordJson FROM recipient_identities WHERE recipient_id = ?',
    [recipientId]
  );
  if (!row) throw new Error(unseenMessage);
  const existing = JSON.parse(row.recordJson) as ContactIdentityRecord;
  validateContactIdentityRecord(existing);
  return existing;
}

async function replacePinnedRecord(
  tx: SqliteExecutor,
  recipientId: string,
  identityType: IdentityType,
  record: ContactIdentityRecord
): Promise<void> {
  validateContactIdentityRecord(record);
  await tx.run(
    `INSERT OR REPLACE INTO recipient_identities
       (recipient_id, identity_type, record_json, updated_at) VALUES (?, ?, ?, ?)`,
    [recipientId, identityType, JSON.stringify(record), Date.now()]
  );
}

export async function acceptContactIdentityRotationAndDeleteSessions(
  ctx: KeyStorageContext,
  address: ProtocolAddress,
  identity: CompositeIdentityV1,
  identityType: IdentityType,
  suppliedCommitment?: Uint8Array
): Promise<ContactIdentityRecord> {
  return await ctx.db.transaction(async (tx) => {
    const recipientId = buildContactIdentityId(address.userId, identityType);
    const existing = await requirePinnedRecord(tx, recipientId, 'Cannot rotate an unseen identity');
    const replacement = acceptRotation(existing, identity, Date.now(), suppliedCommitment);
    await replacePinnedRecord(tx, recipientId, identityType, replacement);

    const sessions = await tx.all<{ sessionId: string }>(
      'SELECT session_id AS sessionId FROM sessions'
    );
    for (const session of sessions) {
      let parsed: ProtocolAddress;
      try {
        parsed = ProtocolAddress.parse(session.sessionId);
      } catch {
        continue;
      }
      if (parsed.userId === address.userId) {
        await tx.run('DELETE FROM sessions WHERE session_id = ?', [session.sessionId]);
      }
    }
    return replacement;
  });
}

export async function verifyContactIdentity(
  ctx: KeyStorageContext,
  address: PeerAddress,
  identity: CompositeIdentityV1,
  identityType: IdentityType,
  suppliedCommitment?: Uint8Array
): Promise<ContactIdentityRecord> {
  return await ctx.db.transaction(async (tx) => {
    const recipientId = buildContactIdentityId(address.userId, identityType);
    const existing = await requirePinnedRecord(tx, recipientId, 'Cannot verify an unseen identity');
    const verified = verifyContactIdentityRecord(
      existing,
      identity,
      Date.now(),
      suppliedCommitment
    );
    await replacePinnedRecord(tx, recipientId, identityType, verified);
    return verified;
  });
}

export async function isTrustedIdentity(
  ctx: KeyStorageContext,
  address: PeerAddress,
  identity: CompositeIdentityV1,
  identityType: IdentityType
): Promise<boolean> {
  const status = evaluateContactIdentityCandidate(
    await modelGetContactIdentity(ctx.db, address.userId, identityType),
    identity
  );
  return status === 'NEW' || status === 'MATCH';
}
