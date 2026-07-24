/**
 * KyberPreKey Model
 *
 * Domain model for PQXDH Kyber prekeys using Drizzle ORM.
 * Kyber prekeys provide post-quantum resistance using CRYSTALS-Kyber-1024.
 *
 * These are "last-resort" signed prekeys that persist until rotated.
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
  kyberPreKeys,
  type NewKyberPreKey,
  eq,
  and,
  isNull,
  count,
  desc,
  sql,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type KyberPreKeyRow = typeof kyberPreKeys.$inferSelect;
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekey-utils';

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get Kyber prekey by key ID.
 *
 * @param keyId - The key ID to look up
 * @returns KyberPreKey instance or null if not found
 */
export async function getKyberPreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(kyberPreKeys)
    .where(
      and(
        eq(kyberPreKeys.identityType, identityType),
        eq(kyberPreKeys.prekeyId, keyId),
        isNull(kyberPreKeys.replacedAt)
      )
    )
    .limit(1);

  return results.length > 0 ? new KyberPreKey(results[0]) : null;
}

/**
 * Get the current (latest) Kyber prekey.
 *
 * Returns the prekey with the highest keyId, which is always the most
 * recently rotated key. Per PQXDH Section 3.2, only one Kyber prekey
 * is active at a time (rotation replaces the previous value).
 *
 * @returns Current KyberPreKey or null if none exists
 */
export async function getCurrentKyberPreKey(
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(kyberPreKeys)
    .where(and(eq(kyberPreKeys.identityType, identityType), isNull(kyberPreKeys.replacedAt)))
    .orderBy(desc(kyberPreKeys.prekeyId))
    .limit(1);

  return results.length > 0 ? new KyberPreKey(results[0]) : null;
}

/**
 * Get all Kyber prekeys.
 *
 * @returns Array of all KyberPreKey instances
 */
export async function getAllKyberPreKeys(
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey[]> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(kyberPreKeys)
    .where(and(eq(kyberPreKeys.identityType, identityType), isNull(kyberPreKeys.replacedAt)));
  return results.map((row) => new KyberPreKey(row));
}

/**
 * Count Kyber prekeys.
 *
 * @returns Number of Kyber prekeys
 */
export async function countKyberPreKeys(identityType: IdentityType = 'aci'): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(kyberPreKeys)
    .where(and(eq(kyberPreKeys.identityType, identityType), isNull(kyberPreKeys.replacedAt)));
  return results[0]?.count ?? 0;
}

/**
 * Mark Kyber prekey as replaced by key ID.
 *
 * Instead of immediately deleting, sets replacedAt = Date.now().
 * Replaced prekeys are excluded from normal queries but retained for
 * in-flight message decryption. Use cullReplacedKyberPreKeys() to
 * permanently delete after a grace period.
 *
 * @param keyId - The key ID to mark replaced
 */
export async function deleteKyberPreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const db = await getDrizzle();
  await db
    .update(kyberPreKeys)
    .set({ replacedAt: Date.now() })
    .where(
      and(
        eq(kyberPreKeys.identityType, identityType),
        eq(kyberPreKeys.prekeyId, keyId),
        isNull(kyberPreKeys.replacedAt)
      )
    );
}

/**
 * Mark all Kyber prekeys as replaced.
 *
 * Sets replacedAt = Date.now() on all active prekeys.
 * They are retained for in-flight message decryption and can be
 * permanently removed with cullReplacedKyberPreKeys().
 */
export async function deleteAllKyberPreKeys(identityType: IdentityType = 'aci'): Promise<void> {
  await markPreKeysReplaced('kyber_prekeys', identityType);
}

/**
 * Get the maximum prekey ID across ALL prekeys (active + stale).
 * Used for key recovery to avoid identifier collisions (PQXDH §4.13).
 *
 * NOTE: Intentionally includes stale prekeys — a stale prekey still
 * occupies its ID until purged, so reusing that ID would cause a collision.
 *
 * @returns Maximum key ID or 0 if none exist
 */
export async function getMaxKyberPreKeyId(identityType: IdentityType = 'aci'): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ maxId: sql<number>`MAX(${kyberPreKeys.prekeyId})` })
    .from(kyberPreKeys)
    .where(eq(kyberPreKeys.identityType, identityType));
  return results[0]?.maxId ?? 0;
}

/**
 * Permanently delete replaced Kyber prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 *
 * Best-effort overwrites decoded private-key bytes before deletion.
 * Delegates to shared cullReplacedPreKeys utility.
 * @param maxReplacedAgeMs - Maximum time a replaced prekey is retained before culling
 * @returns Number of culled prekeys
 */
export async function cullReplacedKyberPreKeys(maxReplacedAgeMs: number): Promise<number> {
  return cullReplacedPreKeys('kyber_prekeys', maxReplacedAgeMs);
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new Kyber prekey.
 *
 * @param params - Kyber prekey parameters
 * @param params.keyId - Unique key identifier
 * @param params.publicKey - Public key (base64 or Uint8Array)
 * @param params.privateKey - Private key (base64 or Uint8Array)
 * @param params.signature - Optional signature (base64 or Uint8Array)
 * @param params.timestamp - Optional timestamp (defaults to now)
 * @returns New KyberPreKey instance (not yet persisted)
 */
export function createKyberPreKey(params: {
  keyId: number;
  publicKey: string | Uint8Array;
  privateKey: string | Uint8Array;
  signature?: string | Uint8Array | null;
  timestamp?: number;
  identityType?: IdentityType;
}): KyberPreKey {
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
  const signature = params.signature
    ? typeof params.signature === 'string'
      ? params.signature
      : Buffer.from(params.signature).toString('base64')
    : null;

  return new KyberPreKey({
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
// KyberPreKey Class
// ============================================================================

/**
 * KyberPreKey domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 * All data is stored in normalized columns (no JSON extraData).
 *
 * @example
 * ```typescript
 * // Store a Kyber prekey
 * const kyber = createKyberPreKey({
 *   keyId: 1,
 *   publicKey: '...',
 *   privateKey: '...',
 *   signature: '...',
 *   timestamp: Date.now(),
 * });
 * await kyber.save();
 *
 * // Get current Kyber prekey
 * const current = await getCurrentKyberPreKey();
 *
 * // Delete by ID
 * await deleteKyberPreKeyByKeyId(1);
 * ```
 */
export class KyberPreKey {
  private readonly data: KyberPreKeyRow;

  constructor(row: KyberPreKeyRow) {
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

  /** Signature (base64 encoded), may be null */
  get signature(): string | null {
    return this.data.signature;
  }

  /** Signature as Uint8Array, may be null */
  get signatureBytes(): Uint8Array | null {
    return this.data.signature ? Uint8Array.from(Buffer.from(this.data.signature, 'base64')) : null;
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
   * Convert to KyberPreKey type (for API compatibility).
   */
  toKyberPreKey(): {
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
      signature: this.signature ?? '',
      timestamp: this.timestamp,
    };
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save Kyber prekey to database.
   */
  async save(): Promise<void> {
    const insertData: NewKyberPreKey = {
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
      `INSERT INTO kyber_prekeys (identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
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
        insertData.signature ?? null,
        insertData.timestamp,
        insertData.createdAt,
        insertData.replacedAt ?? null,
      ]
    );
  }

  /**
   * Delete Kyber prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(): Promise<void> {
    // Best-effort overwrite decoded private-key bytes before deletion.
    secureZero(this.data.privateKey);

    const db = await getDrizzle();
    await db
      .delete(kyberPreKeys)
      .where(
        and(
          eq(kyberPreKeys.identityType, this.data.identityType),
          eq(kyberPreKeys.prekeyId, this.data.prekeyId)
        )
      );
  }
}
