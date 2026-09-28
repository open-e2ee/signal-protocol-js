/**
 * Account-wide operations: the store statistics, the prekey reset of key
 * recovery, and the teardown that empties every SDK table.
 */

import type { IdentityType } from '../../../../keys';
import type { SqliteExecutor } from '../driver';
import { SQLITE_STORE_TABLES } from '../schema';
import { getAllSessionIds, sessionUserId } from '../models';
import { keyStorageError, type KeyStorageContext } from './context';
import { hasIdentityKey } from './identity-keys';
import { getEcOneTimePreKeyCount } from './one-time-prekeys';
import { getEcSignedPreKey } from './signed-prekeys';

export type DetailedStats = {
  sessions: number;
  ecSignedPreKeys: number;
  ecOneTimePreKeys: number;
  kyberPreKeys: number;
  kemOneTimePreKeys: number;
  users: number;
};

export type DeletedPreKeyCounts = {
  ecSignedPreKeys: number;
  ecOneTimePreKeys: number;
  kyberPreKeys: number;
  kemOneTimePreKeys: number;
};

async function count(db: SqliteExecutor, sql: string, params?: readonly string[]): Promise<number> {
  return (await db.first<{ count: number }>(sql, params))?.count ?? 0;
}

/** Empty every SDK table in the caller's transaction. */
async function deleteEveryTable(tx: SqliteExecutor): Promise<void> {
  for (const table of SQLITE_STORE_TABLES) {
    await tx.run(`DELETE FROM ${table}`);
  }
}

/**
 * Clear all encryption keys: every SDK table in one transaction. The database
 * key stays, because the database file stays.
 */
export async function clearAllKeys(ctx: KeyStorageContext): Promise<void> {
  try {
    await ctx.db.transaction(deleteEveryTable);

    ctx.logger.warn('All keys cleared', { category: 'KeyStorage' });
  } catch (error) {
    throw keyStorageError('Failed to clear all keys', error);
  }
}

/** Wipe all Signal Protocol data: every SDK table in one transaction. */
export async function wipeAllSignalProtocolData(ctx: KeyStorageContext): Promise<DetailedStats> {
  try {
    const stats = await getDetailedStats(ctx);

    await ctx.db.transaction(deleteEveryTable);

    ctx.logger.info('All Signal Protocol data wiped', { category: 'KeyStorage', data: stats });

    return stats;
  } catch (error) {
    throw keyStorageError('Failed to wipe Signal Protocol data', error);
  }
}

export async function getStorageStats(ctx: KeyStorageContext): Promise<{
  hasIdentityKey: boolean;
  hasEcSignedPreKey: boolean;
  ecOneTimePreKeysCount: number;
}> {
  try {
    const identityKeyStored = await hasIdentityKey(ctx, 'aci');
    const ecSignedPreKey = await getEcSignedPreKey(ctx, undefined, 'aci');
    const ecOneTimePreKeysCount = await getEcOneTimePreKeyCount(ctx, 'aci');

    return {
      hasIdentityKey: identityKeyStored,
      hasEcSignedPreKey: ecSignedPreKey !== null,
      ecOneTimePreKeysCount,
    };
  } catch (error) {
    throw keyStorageError('Failed to get storage stats', error);
  }
}

export async function getDetailedStats(ctx: KeyStorageContext): Promise<DetailedStats> {
  try {
    const { db } = ctx;
    const [ecSigned, ecOneTime, kyber, kemOneTime, sessions, sessionIds] = await Promise.all([
      count(db, 'SELECT COUNT(*) as count FROM ec_signed_prekeys'),
      count(db, 'SELECT COUNT(*) as count FROM ec_one_time_prekeys'),
      count(db, 'SELECT COUNT(*) as count FROM kyber_prekeys'),
      count(db, 'SELECT COUNT(*) as count FROM kyber_one_time_prekeys'),
      count(db, 'SELECT COUNT(*) as count FROM sessions'),
      getAllSessionIds(db),
    ]);
    // Sesame device records live in the sessions table, so the users are the
    // distinct users that have a session.
    const users = new Set(sessionIds.map(sessionUserId).filter((userId) => userId !== null));

    return {
      sessions,
      ecSignedPreKeys: ecSigned,
      ecOneTimePreKeys: ecOneTime,
      kyberPreKeys: kyber,
      kemOneTimePreKeys: kemOneTime,
      users: users.size,
    };
  } catch (error) {
    throw keyStorageError('Failed to get detailed stats', error);
  }
}

/**
 * Delete all prekeys (signed, one-time, Kyber, KEM one-time) of one identity
 * type, in one transaction.
 *
 * Used during key recovery when persistent MAC failures indicate
 * identifier collision (same keyId, different publicKey).
 * Per PQXDH §4.13, this forces fresh key generation with new IDs.
 *
 * NOTE: This preserves identity keys and sessions.
 */
export async function deleteAllPreKeys(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<DeletedPreKeyCounts> {
  try {
    const stats = await ctx.db.transaction(async (tx) => {
      const counts: DeletedPreKeyCounts = {
        ecSignedPreKeys: await count(
          tx,
          'SELECT COUNT(*) as count FROM ec_signed_prekeys WHERE identity_type = ?',
          [identityType]
        ),
        ecOneTimePreKeys: await count(
          tx,
          'SELECT COUNT(*) as count FROM ec_one_time_prekeys WHERE identity_type = ?',
          [identityType]
        ),
        kyberPreKeys: await count(
          tx,
          'SELECT COUNT(*) as count FROM kyber_prekeys WHERE identity_type = ?',
          [identityType]
        ),
        kemOneTimePreKeys: await count(
          tx,
          'SELECT COUNT(*) as count FROM kyber_one_time_prekeys WHERE identity_type = ?',
          [identityType]
        ),
      };

      await tx.run('DELETE FROM ec_signed_prekeys WHERE identity_type = ?', [identityType]);
      await tx.run('DELETE FROM ec_one_time_prekeys WHERE identity_type = ?', [identityType]);
      await tx.run('DELETE FROM kyber_prekeys WHERE identity_type = ?', [identityType]);
      await tx.run('DELETE FROM kyber_prekey_used WHERE signed_prekey_identity = ?', [
        identityType,
      ]);
      await tx.run('DELETE FROM kyber_one_time_prekeys WHERE identity_type = ?', [identityType]);
      return counts;
    });

    ctx.logger.warn('Deleted all prekeys for key recovery', {
      category: 'KeyStorage',
      data: { ...stats, identityType },
    });

    return stats;
  } catch (error) {
    throw keyStorageError('Failed to delete all prekeys', error);
  }
}
