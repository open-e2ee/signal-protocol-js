/**
 * Shared utilities for prekey replaced-at lifecycle management.
 *
 * Implements replacement timestamps for retained prekeys:
 * - markPreKeysReplaced: Sets replaced_at = now for active prekeys
 * - cullReplacedPreKeys: best-effort overwrites decoded bytes, then deletes
 *
 * All 4 prekey types (signed, kyber, EC one-time, KEM one-time) use these
 * shared functions to avoid code duplication.
 *
 */

import { getRawDatabase } from '../db';
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';

/**
 * Mark all active prekeys as replaced in the given table.
 * Idempotent: only touches rows where replaced_at IS NULL.
 * @param tableName - SQL table name (e.g. 'signed_prekeys')
 * @param identityType - 'aci' or 'pni'
 */
export {};
export async function markPreKeysReplaced(
  tableName: string,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const rawDb = getRawDatabase();
  await rawDb.runAsync(
    `UPDATE ${tableName} SET replaced_at = ? WHERE identity_type = ? AND replaced_at IS NULL`,
    [Date.now(), identityType]
  );
}

/**
 * Permanently delete replaced prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replaced_at far in the future (clock-skew protection).
 * Best-effort overwrites decoded private-key bytes before deletion.
 * Uses maxUnacknowledgedSessionAge (30d) as the base delay.
 *
 * @param tableName - SQL table name (e.g. 'signed_prekeys')
 * @param maxReplacedAgeMs - Maximum age in ms before culling
 * @param identityType - Optional identity type filter
 * @returns Number of culled prekeys
 */
export async function cullReplacedPreKeys(
  tableName: string,
  maxReplacedAgeMs: number,
  identityType?: IdentityType
): Promise<number> {
  const rawDb = getRawDatabase();
  const now = Date.now();
  const pastCutoff = now - maxReplacedAgeMs;
  const futureCutoff = now + maxReplacedAgeMs; // clock-skew protection
  let culledCount = 0;

  await rawDb.withTransactionAsync(async () => {
    const identityClause = identityType ? ' AND identity_type = ?' : '';
    const params = identityType
      ? [pastCutoff, futureCutoff, identityType]
      : [pastCutoff, futureCutoff];

    // Fetch keys to overwrite decoded bytes where possible.
    const rows = await rawDb.getAllAsync<{ private_key: string }>(
      `SELECT private_key FROM ${tableName}
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)${identityClause}`,
      params
    );

    for (const row of rows) {
      secureZero(row.private_key);
    }

    if (rows.length === 0) return;

    const result = await rawDb.runAsync(
      `DELETE FROM ${tableName}
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)${identityClause}`,
      params
    );
    culledCount = result.changes ?? 0;
  });

  return culledCount;
}
