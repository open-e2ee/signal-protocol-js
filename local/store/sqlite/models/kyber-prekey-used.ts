/**
 * KyberPreKeyUsed: PQXDH replay detection
 *
 * Stores (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuples.
 * Duplicate insert = replay attack -> throw ReusedBaseKeyError.
 */

import type { SqliteExecutor } from '../driver';
import { classifySqliteError } from '../errors';
import { ReusedBaseKeyError } from '../../kyber-prekey-lifecycle';
import { bytesToBase64 } from '../../../../internal/crypto/utils';

// ============================================================================
// Error
// ============================================================================

/**
 * The store throws this when it detects a PQXDH base key reuse.
 *
 * This indicates a replay attack. The table already holds the same
 * `(kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey)` tuple.
 */
export { ReusedBaseKeyError } from '../../kyber-prekey-lifecycle';

// ============================================================================
// Functions
// ============================================================================

/**
 * Mark a Kyber prekey as used with the given session parameters.
 *
 * Inserts a (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuple.
 * If the tuple already exists (PRIMARY KEY constraint violation), throws
 * ReusedBaseKeyError, indicating a PQXDH replay attack.
 *
 * @param kyberPreKeyId - The Kyber prekey ID that the session used
 * @param signedPreKeyId - The signed prekey ID used in the session
 * @param baseKeyBytes - The sender's ephemeral base key
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 */
export async function markKyberPreKeyUsed(
  db: SqliteExecutor,
  kyberPreKeyId: number,
  signedPreKeyId: number,
  baseKeyBytes: Uint8Array,
  identityType: string = 'aci'
): Promise<void> {
  const baseKey = bytesToBase64(baseKeyBytes);

  const parent = await db.first<{ id: number }>(
    'SELECT id FROM kyber_prekeys WHERE identity_type = ? AND prekey_id = ? LIMIT 1',
    [identityType, kyberPreKeyId]
  );
  if (!parent) throw new Error(`Kyber prekey ${kyberPreKeyId} is not retained`);
  try {
    await db.run(
      `INSERT INTO kyber_prekey_used
       (kyber_prekey_row_id, signed_prekey_identity, signed_prekey_id, base_key)
       VALUES (?, ?, ?, ?)`,
      [parent.id, identityType, signedPreKeyId, baseKey]
    );
  } catch (error: unknown) {
    // Duplicate tuple = PQXDH replay attack
    if (classifySqliteError(error) === 'unique-constraint') {
      throw new ReusedBaseKeyError(kyberPreKeyId, signedPreKeyId);
    }
    throw error;
  }
}

/**
 * Delete all Kyber prekey used records.
 *
 * Used for cleanup and deterministic inspection.
 */
export async function deleteAllKyberPreKeyUsed(db: SqliteExecutor): Promise<void> {
  await db.run('DELETE FROM kyber_prekey_used');
}
