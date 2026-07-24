/**
 * EcOneTimePreKey Model
 *
 * Domain model for Signal Protocol EC one-time prekeys using Drizzle ORM.
 * EC one-time prekeys are single-use keys consumed during session establishment.
 *
 *
 */

import {
  getDrizzle,
  getRawDatabase,
  ecOneTimePreKeys,
  type NewEcOneTimePreKey,
  eq,
  and,
  count,
  inArray,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type EcOneTimePreKeyRow = typeof ecOneTimePreKeys.$inferSelect;
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekey-utils';

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get EC one-time prekey by key ID.
 *
 * @param keyId - The key ID to look up
 * @returns EcOneTimePreKey instance or null if not found
 */
export async function getEcOneTimePreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<EcOneTimePreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(ecOneTimePreKeys)
    .where(
      and(eq(ecOneTimePreKeys.identityType, identityType), eq(ecOneTimePreKeys.prekeyId, keyId))
    )
    .limit(1);

  return results.length > 0 ? new EcOneTimePreKey(results[0]) : null;
}

/**
 * Get all EC one-time prekeys.
 *
 * @returns Array of all EcOneTimePreKey instances
 */
export async function getAllEcOneTimePreKeys(
  identityType: IdentityType = 'aci'
): Promise<EcOneTimePreKey[]> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(ecOneTimePreKeys)
    .where(eq(ecOneTimePreKeys.identityType, identityType));
  return results.map((row) => new EcOneTimePreKey(row));
}

/**
 * Count EC one-time prekeys.
 *
 * @returns Number of EC one-time prekeys
 */
export async function countEcOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(ecOneTimePreKeys)
    .where(eq(ecOneTimePreKeys.identityType, identityType));
  return results[0]?.count ?? 0;
}

/**
 * Delete EC one-time prekey by key ID.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param keyId - The key ID to delete
 */
export async function deleteEcOneTimePreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch the prekey to overwrite decoded private-key bytes where possible.
    const prekey = await getEcOneTimePreKeyByKeyId(keyId, identityType);
    if (prekey) {
      secureZero(prekey.privateKey);
    }

    const db = await getDrizzle();
    await db
      .delete(ecOneTimePreKeys)
      .where(
        and(eq(ecOneTimePreKeys.identityType, identityType), eq(ecOneTimePreKeys.prekeyId, keyId))
      );
  });
}

/**
 * Delete multiple EC one-time prekeys by key IDs.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param keyIds - Array of key IDs to delete
 */
export async function deleteEcOneTimePreKeysByKeyIds(
  keyIds: number[],
  identityType: IdentityType = 'aci'
): Promise<void> {
  if (keyIds.length === 0) return;

  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const db = await getDrizzle();
    const results = await db
      .select()
      .from(ecOneTimePreKeys)
      .where(
        and(
          eq(ecOneTimePreKeys.identityType, identityType),
          inArray(ecOneTimePreKeys.prekeyId, keyIds)
        )
      );

    for (const row of results) {
      const prekey = new EcOneTimePreKey(row);
      secureZero(prekey.privateKey);
    }

    await db
      .delete(ecOneTimePreKeys)
      .where(
        and(
          eq(ecOneTimePreKeys.identityType, identityType),
          inArray(ecOneTimePreKeys.prekeyId, keyIds)
        )
      );
  });
}

/**
 * Delete all EC one-time prekeys.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 */
export async function deleteAllEcOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const all = await getAllEcOneTimePreKeys(identityType);
    for (const prekey of all) {
      secureZero(prekey.privateKey);
    }

    const db = await getDrizzle();
    await db.delete(ecOneTimePreKeys).where(eq(ecOneTimePreKeys.identityType, identityType));
  });
}

/**
 * Store a batch of EC one-time prekeys.
 *
 * @param prekeys - Array of EcOneTimePreKey instances to store
 */
export async function storeBatchEcOneTimePreKeys(prekeys: EcOneTimePreKey[]): Promise<void> {
  if (prekeys.length === 0) return;

  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    for (const pk of prekeys) {
      await pk.save();
    }
  });
}

/**
 * Mark all active EC one-time prekeys as replaced.
 * Called before generating new EC one-time prekeys.
 * @param identityType - 'aci' or 'pni'
 */
export async function markAllEcOneTimePreKeysReplaced(
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced('ec_one_time_prekeys', identityType);
}

/**
 * Permanently delete replaced EC one-time prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 * Best-effort overwrites decoded private-key bytes before deletion.
 * @param maxReplacedAgeMs - Maximum age in ms before culling
 * @param identityType - 'aci' or 'pni'
 * @returns Number of culled prekeys
 */
export async function cullReplacedEcOneTimePreKeys(
  maxReplacedAgeMs: number,
  identityType: IdentityType = 'aci'
): Promise<number> {
  return cullReplacedPreKeys('ec_one_time_prekeys', maxReplacedAgeMs, identityType);
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new EC one-time prekey.
 *
 * @param params - EC one-time prekey parameters
 * @param params.keyId - Unique key identifier
 * @param params.publicKey - Public key (base64 or Uint8Array)
 * @param params.privateKey - Private key (base64 or Uint8Array)
 * @returns New EcOneTimePreKey instance (not yet persisted)
 */
export function createEcOneTimePreKey(params: {
  keyId: number;
  publicKey: string | Uint8Array;
  privateKey: string | Uint8Array;
  identityType?: IdentityType;
}): EcOneTimePreKey {
  const now = Date.now();

  const publicKey =
    typeof params.publicKey === 'string'
      ? params.publicKey
      : Buffer.from(params.publicKey).toString('base64');
  const privateKey =
    typeof params.privateKey === 'string'
      ? params.privateKey
      : Buffer.from(params.privateKey).toString('base64');

  return new EcOneTimePreKey({
    id: 0, // Auto-increment
    identityType: params.identityType ?? 'aci',
    prekeyId: params.keyId,
    publicKey,
    privateKey,
    createdAt: now,
    replacedAt: null,
  });
}

// ============================================================================
// EcOneTimePreKey Class
// ============================================================================

/**
 * EcOneTimePreKey domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 *
 * @example
 * ```typescript
 * // Store batch of EC one-time prekeys
 * const prekeys = [
 *   createEcOneTimePreKey({ keyId: 1, publicKey: '...', privateKey: '...' }),
 *   createEcOneTimePreKey({ keyId: 2, publicKey: '...', privateKey: '...' }),
 * ];
 * await storeBatchEcOneTimePreKeys(prekeys);
 *
 * // Get all prekeys
 * const all = await getAllEcOneTimePreKeys();
 *
 * // Remove consumed prekey
 * await deleteEcOneTimePreKeyByKeyId(1);
 * ```
 */
export class EcOneTimePreKey {
  private readonly data: EcOneTimePreKeyRow;

  constructor(row: EcOneTimePreKeyRow) {
    this.data = { ...row };
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Key ID */
  get keyId(): number {
    return this.data.prekeyId;
  }

  /** Public key (base64 encoded) */
  get publicKey(): string {
    return this.data.publicKey;
  }

  /** Public key as Uint8Array */
  get publicKeyBytes(): Uint8Array {
    return Uint8Array.from(Buffer.from(this.data.publicKey, 'base64'));
  }

  /** Private key (base64 encoded) */
  get privateKey(): string {
    return this.data.privateKey;
  }

  /** Private key as Uint8Array */
  get privateKeyBytes(): Uint8Array {
    return Uint8Array.from(Buffer.from(this.data.privateKey, 'base64'));
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  // ============================================================================
  // Serialization
  // ============================================================================

  /**
   * Convert to EcOneTimePreKey type (for API compatibility).
   */
  toEcOneTimePreKey(): {
    keyId: number;
    publicKey: string;
    privateKey: string;
  } {
    return {
      keyId: this.keyId,
      publicKey: this.publicKey,
      privateKey: this.privateKey,
    };
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save EC one-time prekey to database.
   */
  async save(): Promise<void> {
    const insertData: NewEcOneTimePreKey = {
      identityType: this.data.identityType,
      prekeyId: this.data.prekeyId,
      publicKey: this.data.publicKey,
      privateKey: this.data.privateKey,
      createdAt: this.data.createdAt,
      replacedAt: this.data.replacedAt ?? null,
    };

    // Use raw SQL for upsert on the composite unique index (identity_type, prekey_id)
    const rawDb = getRawDatabase();
    await rawDb.runAsync(
      `INSERT INTO ec_one_time_prekeys (identity_type, prekey_id, public_key, private_key, created_at, replaced_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (identity_type, prekey_id) DO UPDATE SET
         public_key = excluded.public_key,
         private_key = excluded.private_key,
         created_at = excluded.created_at`,
      [
        insertData.identityType ?? 'aci',
        insertData.prekeyId,
        insertData.publicKey,
        insertData.privateKey,
        insertData.createdAt,
        insertData.replacedAt ?? null,
      ]
    );
  }

  /**
   * Delete EC one-time prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(): Promise<void> {
    // Best-effort overwrite decoded private-key bytes before deletion.
    secureZero(this.data.privateKey);

    const db = await getDrizzle();
    await db
      .delete(ecOneTimePreKeys)
      .where(
        and(
          eq(ecOneTimePreKeys.identityType, this.data.identityType),
          eq(ecOneTimePreKeys.prekeyId, this.data.prekeyId)
        )
      );
  }
}
