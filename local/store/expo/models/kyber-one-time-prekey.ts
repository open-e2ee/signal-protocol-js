/**
 * KyberOneTimePreKey Model
 *
 * Domain model for PQXDH Kyber one-time prekeys using Drizzle ORM.
 * Kyber one-time prekeys are consumed on use, providing per-session
 * post-quantum forward secrecy.
 *
 * Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys.
 *
 * Schema (fully normalized, no JSON blobs):
 * - Uses prekey_id column as the authoritative keyId
 * - Uses timestamp column for logical key creation time
 *
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import {
  getDrizzle,
  getRawDatabase,
  kyberOneTimePreKeys,
  type NewKyberOneTimePreKey,
  eq,
  and,
  count,
  inArray,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type KyberOneTimePreKeyRow = typeof kyberOneTimePreKeys.$inferSelect;
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekey-utils';

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get Kyber one-time prekey by key ID.
 * Used during session establishment for decapsulation.
 *
 * @param keyId - The key ID to look up
 * @returns KyberOneTimePreKey instance or null if not found
 */
export async function getKyberOneTimePreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<KyberOneTimePreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(kyberOneTimePreKeys)
    .where(
      and(
        eq(kyberOneTimePreKeys.identityType, identityType),
        eq(kyberOneTimePreKeys.prekeyId, keyId)
      )
    )
    .limit(1);

  return results.length > 0 ? new KyberOneTimePreKey(results[0]) : null;
}

/**
 * Get all Kyber one-time prekeys.
 *
 * @returns Array of all KyberOneTimePreKey instances
 */
export async function getAllKyberOneTimePreKeys(
  identityType: IdentityType = 'aci'
): Promise<KyberOneTimePreKey[]> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(kyberOneTimePreKeys)
    .where(eq(kyberOneTimePreKeys.identityType, identityType));
  return results.map((row) => new KyberOneTimePreKey(row));
}

/**
 * Count Kyber one-time prekeys.
 *
 * @returns Number of Kyber one-time prekeys
 */
export async function countKyberOneTimePreKeys(
  identityType: IdentityType = 'aci'
): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(kyberOneTimePreKeys)
    .where(eq(kyberOneTimePreKeys.identityType, identityType));
  return results[0]?.count ?? 0;
}

/**
 * Delete Kyber one-time prekey by key ID.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * CRITICAL: Must be called immediately after successful decapsulation
 * to provide per-session post-quantum forward secrecy.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param keyId - The key ID to delete
 */
export async function deleteKyberOneTimePreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch the prekey to overwrite decoded private-key bytes where possible.
    const prekey = await getKyberOneTimePreKeyByKeyId(keyId, identityType);
    if (prekey) {
      secureZero(prekey.privateKey);
    }

    const db = await getDrizzle();
    await db
      .delete(kyberOneTimePreKeys)
      .where(
        and(
          eq(kyberOneTimePreKeys.identityType, identityType),
          eq(kyberOneTimePreKeys.prekeyId, keyId)
        )
      );
  });
}

/**
 * Delete multiple Kyber one-time prekeys by key IDs.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param keyIds - Array of key IDs to delete
 */
export async function deleteKyberOneTimePreKeysByKeyIds(
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
      .from(kyberOneTimePreKeys)
      .where(
        and(
          eq(kyberOneTimePreKeys.identityType, identityType),
          inArray(kyberOneTimePreKeys.prekeyId, keyIds)
        )
      );

    for (const row of results) {
      const prekey = new KyberOneTimePreKey(row);
      secureZero(prekey.privateKey);
    }

    await db
      .delete(kyberOneTimePreKeys)
      .where(
        and(
          eq(kyberOneTimePreKeys.identityType, identityType),
          inArray(kyberOneTimePreKeys.prekeyId, keyIds)
        )
      );
  });
}

/**
 * Delete all Kyber one-time prekeys.
 * Best-effort overwrites decoded private-key bytes before deletion.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 */
export async function deleteAllKyberOneTimePreKeys(
  identityType: IdentityType = 'aci'
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const all = await getAllKyberOneTimePreKeys(identityType);
    for (const prekey of all) {
      secureZero(prekey.privateKey);
    }

    const db = await getDrizzle();
    await db.delete(kyberOneTimePreKeys).where(eq(kyberOneTimePreKeys.identityType, identityType));
  });
}

/**
 * Store a batch of Kyber one-time prekeys.
 *
 * @param prekeys - Array of KyberOneTimePreKey instances to store
 */
export async function storeBatchKyberOneTimePreKeys(prekeys: KyberOneTimePreKey[]): Promise<void> {
  if (prekeys.length === 0) return;

  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    for (const pk of prekeys) {
      await pk.save();
    }
  });
}

/**
 * Mark all active Kyber one-time prekeys as replaced.
 * Called before generating new Kyber one-time prekeys.
 * @param identityType - 'aci' or 'pni'
 */
export async function markAllKyberOneTimePreKeysReplaced(
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced('kyber_one_time_prekeys', identityType);
}

/**
 * Permanently delete replaced Kyber one-time prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 * Best-effort overwrites decoded private-key bytes before deletion.
 * @param maxReplacedAgeMs - Maximum age in ms before culling
 * @param identityType - 'aci' or 'pni'
 * @returns Number of culled prekeys
 */
export async function cullReplacedKyberOneTimePreKeys(
  maxReplacedAgeMs: number,
  identityType: IdentityType = 'aci'
): Promise<number> {
  return cullReplacedPreKeys('kyber_one_time_prekeys', maxReplacedAgeMs, identityType);
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new Kyber one-time prekey.
 *
 * @param params - Kyber one-time prekey parameters
 * @param params.keyId - Unique key identifier
 * @param params.publicKey - Public key (base64 or Uint8Array)
 * @param params.privateKey - Private key (base64 or Uint8Array)
 * @param params.signature - Signature (base64 or Uint8Array)
 * @param params.timestamp - Optional timestamp (defaults to now)
 * @returns New KyberOneTimePreKey instance (not yet persisted)
 */
export function createKyberOneTimePreKey(params: {
  keyId: number;
  publicKey: string | Uint8Array;
  privateKey: string | Uint8Array;
  signature: string | Uint8Array;
  timestamp?: number;
  identityType?: IdentityType;
}): KyberOneTimePreKey {
  const now = Date.now();
  const timestamp = params.timestamp ?? now;

  const publicKey =
    typeof params.publicKey === 'string'
      ? params.publicKey
      : Buffer.from(params.publicKey).toString('base64');
  const privateKey =
    typeof params.privateKey === 'string'
      ? params.privateKey
      : Buffer.from(params.privateKey).toString('base64');
  const signature =
    typeof params.signature === 'string'
      ? params.signature
      : Buffer.from(params.signature).toString('base64');

  return new KyberOneTimePreKey({
    id: 0, // Auto-increment
    identityType: params.identityType ?? 'aci',
    prekeyId: params.keyId,
    publicKey,
    privateKey,
    signature,
    timestamp,
    createdAt: now,
    replacedAt: null,
  });
}

// ============================================================================
// KyberOneTimePreKey Class
// ============================================================================

/**
 * KyberOneTimePreKey domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 * All data is stored in normalized columns (no JSON extraData).
 *
 * @example
 * ```typescript
 * // Store batch of Kyber one-time prekeys
 * const prekeys = [
 *   createKyberOneTimePreKey({ keyId: 1, publicKey: '...', privateKey: '...', signature: '...' }),
 *   createKyberOneTimePreKey({ keyId: 2, publicKey: '...', privateKey: '...', signature: '...' }),
 * ];
 * await storeBatchKyberOneTimePreKeys(prekeys);
 *
 * // Get specific prekey for decapsulation
 * const prekey = await getKyberOneTimePreKeyByKeyId(1);
 *
 * // Remove consumed prekey (CRITICAL for forward secrecy)
 * await deleteKyberOneTimePreKeyByKeyId(1);
 * ```
 */
export class KyberOneTimePreKey {
  private readonly data: KyberOneTimePreKeyRow;

  constructor(row: KyberOneTimePreKeyRow) {
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

  /** Signature (base64 encoded) */
  get signature(): string {
    return this.data.signature;
  }

  /** Signature as Uint8Array */
  get signatureBytes(): Uint8Array {
    return Uint8Array.from(Buffer.from(this.data.signature, 'base64'));
  }

  /** Timestamp when key was created (logical time, may differ from DB insert time) */
  get timestamp(): number {
    return this.data.timestamp;
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  // ============================================================================
  // Serialization
  // ============================================================================

  /**
   * Convert to KemOneTimePreKey type (for API compatibility).
   */
  toKemOneTimePreKey(): {
    keyId: number;
    publicKey: string;
    privateKey: string;
    signature: string;
    timestamp: number;
  } {
    return {
      keyId: this.keyId,
      publicKey: this.publicKey,
      privateKey: this.privateKey,
      signature: this.signature,
      timestamp: this.timestamp,
    };
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save Kyber one-time prekey to database.
   */
  async save(): Promise<void> {
    const insertData: NewKyberOneTimePreKey = {
      identityType: this.data.identityType,
      prekeyId: this.data.prekeyId,
      publicKey: this.data.publicKey,
      privateKey: this.data.privateKey,
      signature: this.data.signature,
      timestamp: this.data.timestamp,
      createdAt: this.data.createdAt,
      replacedAt: this.data.replacedAt ?? null,
    };

    // Use raw SQL for upsert on the composite unique index (identity_type, prekey_id)
    const rawDb = getRawDatabase();
    await rawDb.runAsync(
      `INSERT INTO kyber_one_time_prekeys (identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (identity_type, prekey_id) DO UPDATE SET
         public_key = excluded.public_key,
         private_key = excluded.private_key,
         signature = excluded.signature,
         timestamp = excluded.timestamp,
         created_at = excluded.created_at`,
      [
        insertData.identityType ?? 'aci',
        insertData.prekeyId,
        insertData.publicKey,
        insertData.privateKey,
        insertData.signature,
        insertData.timestamp,
        insertData.createdAt,
        insertData.replacedAt ?? null,
      ]
    );
  }

  /**
   * Delete Kyber one-time prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   *
   * CRITICAL: Must be called immediately after successful decapsulation
   * to provide per-session post-quantum forward secrecy.
   */
  async delete(): Promise<void> {
    // Best-effort overwrite decoded private-key bytes before deletion.
    secureZero(this.data.privateKey);

    const db = await getDrizzle();
    await db
      .delete(kyberOneTimePreKeys)
      .where(
        and(
          eq(kyberOneTimePreKeys.identityType, this.data.identityType),
          eq(kyberOneTimePreKeys.prekeyId, this.data.prekeyId)
        )
      );
  }
}
