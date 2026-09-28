/**
 * Replacement lifecycle shared by the four prekey tables.
 *
 * - markPreKeysReplaced: sets replaced_at = now on the active prekeys
 * - cullReplacedPreKeys: best-effort overwrites decoded bytes, then deletes
 */

import type { SqliteExecutor } from '../driver';
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';

export type PreKeyTable =
  | 'ec_signed_prekeys'
  | 'ec_one_time_prekeys'
  | 'kyber_prekeys'
  | 'kyber_one_time_prekeys';

/**
 * Mark all active prekeys as replaced in the given table.
 * Idempotent: only touches rows where replaced_at IS NULL.
 */
export async function markPreKeysReplaced(
  db: SqliteExecutor,
  tableName: PreKeyTable,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.run(
    `UPDATE ${tableName} SET replaced_at = ? WHERE identity_type = ? AND replaced_at IS NULL`,
    [Date.now(), identityType]
  );
}

/**
 * Permanently delete replaced prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replaced_at far in the future (clock-skew protection).
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * @returns Number of culled prekeys
 */
export async function cullReplacedPreKeys(
  db: SqliteExecutor,
  tableName: PreKeyTable,
  maxReplacedAgeMs: number,
  identityType?: IdentityType
): Promise<number> {
  const now = Date.now();
  const pastCutoff = now - maxReplacedAgeMs;
  const futureCutoff = now + maxReplacedAgeMs; // clock-skew protection
  const identityClause = identityType ? ' AND identity_type = ?' : '';
  const params = identityType
    ? [pastCutoff, futureCutoff, identityType]
    : [pastCutoff, futureCutoff];
  const where = `WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)${identityClause}`;

  return db.transaction(async (tx) => {
    // Fetch keys to overwrite decoded bytes where possible.
    const rows = await tx.all<{ privateKey: string }>(
      `SELECT private_key AS privateKey FROM ${tableName} ${where}`,
      params
    );

    for (const row of rows) {
      secureZero(row.privateKey);
    }

    if (rows.length === 0) return 0;

    return tx.run(`DELETE FROM ${tableName} ${where}`, params);
  });
}
