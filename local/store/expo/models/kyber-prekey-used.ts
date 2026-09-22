/**
 * KyberPreKeyUsed: PQXDH replay detection
 *
 * Stores (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuples.
 * Duplicate insert = replay attack -> throw ReusedBaseKeyError.
 *
 */

import { and, eq, getDrizzle, kyberPreKeys, kyberPreKeyUsed } from '../db';
import { ReusedBaseKeyError } from '../../kyber-prekey-lifecycle';

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
  kyberPreKeyId: number,
  signedPreKeyId: number,
  baseKeyBytes: Uint8Array,
  identityType: string = 'aci'
): Promise<void> {
  const baseKey = Buffer.from(baseKeyBytes).toString('base64');

  try {
    const db = await getDrizzle();
    const parent = await db
      .select({ id: kyberPreKeys.id })
      .from(kyberPreKeys)
      .where(
        and(eq(kyberPreKeys.identityType, identityType), eq(kyberPreKeys.prekeyId, kyberPreKeyId))
      )
      .limit(1);
    if (!parent[0]) throw new Error(`Kyber prekey ${kyberPreKeyId} is not retained`);
    await db
      .insert(kyberPreKeyUsed)
      .values({
        kyberPreKeyRowId: parent[0].id,
        signedPreKeyIdentity: identityType,
        signedPreKeyId,
        baseKey,
      });
  } catch (error: unknown) {
    // Duplicate tuple = PQXDH replay attack
    const errorMessage = error instanceof Error ? error.message : '';
    if (errorMessage.includes('UNIQUE constraint failed') || errorMessage.includes('PRIMARY KEY')) {
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
export async function deleteAllKyberPreKeyUsed(): Promise<void> {
  const db = await getDrizzle();
  await db.delete(kyberPreKeyUsed);
}
