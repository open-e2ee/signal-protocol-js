/**
 * The atomic session and trust commit of an accepted session setup. One
 * transaction pins the contact identity, stores the session, consumes the
 * one-time prekeys, records the Kyber prekey use, and keeps the received
 * content, or does none of these.
 */

import { createUnverifiedContactIdentityRecord, evaluateContactIdentityCandidate } from '../../../../keys/identity';
import type { SessionTrustCommit } from '../../../../types';
import { ProtocolAddress } from '../../../../types/address';
import { assertCurrentSessionRecord } from '../../../../types/session';
import { bytesToBase64 } from '../../../../internal/crypto/utils';
import {
  ReusedBaseKeyError,
  getContactIdentity,
  getEcOneTimePreKeyByKeyId,
  getKyberOneTimePreKeyByKeyId,
  saveContactIdentity,
  serializeSessionRecord,
} from '../models';
import type { KeyStorageContext } from './context';
import { setReceivedContent } from './metadata';

export async function commitSessionTrust(
  ctx: KeyStorageContext,
  commit: SessionTrustCommit
): Promise<void> {
  assertCurrentSessionRecord(commit.record);
  const sessionId = ProtocolAddress.toString(commit.address);
  const serialized = serializeSessionRecord(commit.record);
  const now = Date.now();
  await ctx.db.transaction(async (tx) => {
    const existingContact = await getContactIdentity(
      tx,
      commit.address.userId,
      commit.contactIdentityType
    );
    const contactStatus = evaluateContactIdentityCandidate(existingContact, commit.contactIdentity);
    if (contactStatus !== 'NEW' && contactStatus !== 'MATCH') {
      throw new Error(
        `Atomic session/trust commit rejected contact identity status ${contactStatus}`
      );
    }
    if (
      commit.oneTimePreKeyId !== undefined &&
      !(await getEcOneTimePreKeyByKeyId(tx, commit.oneTimePreKeyId, commit.localIdentityType))
    ) {
      throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
    }
    if (
      commit.kemOneTimePreKeyId !== undefined &&
      !(await getKyberOneTimePreKeyByKeyId(tx, commit.kemOneTimePreKeyId, commit.localIdentityType))
    ) {
      throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
    }
    let kyberParentRowId: number | undefined;
    let kyberBaseKey: string | undefined;
    if (commit.kyberPreKeyUse) {
      const parent = await tx.first<{ id: number }>(
        `SELECT id FROM kyber_prekeys
         WHERE identity_type = ? AND prekey_id = ? AND instance_id = ?`,
        [
          commit.localIdentityType,
          commit.kyberPreKeyUse.kyberPreKeyId,
          commit.kyberPreKeyUse.kyberPreKeyInstanceId,
        ]
      );
      if (!parent) {
        throw new Error('Atomic session/trust commit rejected a Kyber prekey instance mismatch');
      }
      kyberParentRowId = parent.id;
      kyberBaseKey = bytesToBase64(commit.kyberPreKeyUse.baseKeyBytes);
      const reused = await tx.first<{ present: number }>(
        `SELECT 1 AS present FROM kyber_prekey_used
         WHERE kyber_prekey_row_id = ? AND signed_prekey_identity = ?
         AND signed_prekey_id = ? AND base_key = ?`,
        [
          kyberParentRowId,
          commit.localIdentityType,
          commit.kyberPreKeyUse.signedPreKeyId,
          kyberBaseKey,
        ]
      );
      if (reused) {
        throw new ReusedBaseKeyError(
          commit.kyberPreKeyUse.kyberPreKeyId,
          commit.kyberPreKeyUse.signedPreKeyId
        );
      }
    }
    if (contactStatus === 'NEW') {
      await saveContactIdentity(
        tx,
        commit.address.userId,
        createUnverifiedContactIdentityRecord(commit.contactIdentity, now),
        commit.contactIdentityType
      );
    }
    await tx.run(
      `INSERT INTO sessions (session_id, identity_type, record, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(session_id) DO UPDATE SET
           identity_type = excluded.identity_type,
           record = excluded.record,
           updated_at = excluded.updated_at`,
      [sessionId, commit.contactIdentityType, serialized, now, now]
    );
    if (commit.oneTimePreKeyId !== undefined) {
      await tx.run('DELETE FROM ec_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
        commit.localIdentityType,
        commit.oneTimePreKeyId,
      ]);
    }
    if (commit.kemOneTimePreKeyId !== undefined) {
      await tx.run('DELETE FROM kyber_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
        commit.localIdentityType,
        commit.kemOneTimePreKeyId,
      ]);
    }
    if (commit.kyberPreKeyUse && kyberParentRowId !== undefined && kyberBaseKey) {
      await tx.run(
        `INSERT INTO kyber_prekey_used
         (kyber_prekey_row_id, signed_prekey_identity, signed_prekey_id, base_key)
         VALUES (?, ?, ?, ?)`,
        [kyberParentRowId, commit.localIdentityType, commit.kyberPreKeyUse.signedPreKeyId, kyberBaseKey]
      );
    }
    if (commit.receivedContent) await setReceivedContent(tx, commit.receivedContent);
  });
}
