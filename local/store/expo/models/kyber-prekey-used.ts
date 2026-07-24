/**
 * KyberPreKeyUsed — PQXDH replay detection
 *
 * Stores (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuples.
 * Duplicate insert = replay attack -> throw ReusedBaseKeyError.
 *
 */

import { getDrizzle, kyberPreKeyUsed } from '../db';

// ============================================================================
// Error
// ============================================================================

/**
 * Thrown when a PQXDH base key reuse is detected.
 *
 * This indicates a replay attack: the same (kyberPreKeyId, signedPreKeyIdentity,
 * signedPreKeyId, baseKey) tuple has been seen before.
 */
export {};
export class ReusedBaseKeyError extends Error {
  constructor(kyberPreKeyId: number, signedPreKeyId: number) {
    super(
      `Reused base key detected for Kyber prekey ${kyberPreKeyId} with signed prekey ${signedPreKeyId}`
    );
    this.name = 'ReusedBaseKeyError';
  }
}

// ============================================================================
// Functions
// ============================================================================

/**
 * Mark a Kyber prekey as used with the given session parameters.
 *
 * Inserts a (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuple.
 * If the tuple already exists (PRIMARY KEY constraint violation), throws
 * ReusedBaseKeyError — indicating a PQXDH replay attack.
 *
 * @param kyberPreKeyId - The Kyber prekey ID that was used
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
    await db.insert(kyberPreKeyUsed).values({
      kyberPreKeyId,
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
