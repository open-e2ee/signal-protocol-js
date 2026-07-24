/**
 * EcSignedPreKey Model
 *
 * Domain model for Signal Protocol EC signed prekeys using Drizzle ORM.
 * EC signed prekeys are medium-term keys rotated weekly.
 *
 * Schema (fully normalized, no JSON blobs):
 * - Uses prekey_id column as the authoritative keyId
 * - Uses timestamp column for logical key creation time
 *
 *
 */

import {
  getDrizzle,
  getRawDatabase,
  ecSignedPreKeys,
  type NewEcSignedPreKey,
  eq,
  and,
  isNull,
  desc,
  count,
  sql,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type EcSignedPreKeyRow = typeof ecSignedPreKeys.$inferSelect;
import { secureZero } from '../../../../internal/crypto';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../../types/protocol-config';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekey-utils';

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get EC signed prekey by key ID.
 *
 * @param keyId - The key ID to look up
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns EcSignedPreKey instance or null if not found
 */
export async function getEcSignedPreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(ecSignedPreKeys)
    .where(
      and(
        eq(ecSignedPreKeys.identityType, identityType),
        eq(ecSignedPreKeys.prekeyId, keyId),
        isNull(ecSignedPreKeys.replacedAt)
      )
    )
    .limit(1);

  return results.length > 0 ? new EcSignedPreKey(results[0]) : null;
}

/**
 * Get the current (most recent) EC signed prekey.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Current EcSignedPreKey or null if none exists
 */
export async function getCurrentEcSignedPreKey(
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(ecSignedPreKeys)
    .where(and(eq(ecSignedPreKeys.identityType, identityType), isNull(ecSignedPreKeys.replacedAt)))
    .orderBy(desc(ecSignedPreKeys.createdAt), desc(ecSignedPreKeys.prekeyId))
    .limit(1);

  return results.length > 0 ? new EcSignedPreKey(results[0]) : null;
}

/**
 * Get all EC signed prekeys.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Array of all EcSignedPreKey instances
 */
export async function getAllEcSignedPreKeys(
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey[]> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(ecSignedPreKeys)
    .where(and(eq(ecSignedPreKeys.identityType, identityType), isNull(ecSignedPreKeys.replacedAt)))
    .orderBy(desc(ecSignedPreKeys.createdAt));

  return results.map((row) => new EcSignedPreKey(row));
}

/**
 * Count EC signed prekeys.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Number of EC signed prekeys
 */
export async function countEcSignedPreKeys(identityType: IdentityType = 'aci'): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(ecSignedPreKeys)
    .where(and(eq(ecSignedPreKeys.identityType, identityType), isNull(ecSignedPreKeys.replacedAt)));
  return results[0]?.count ?? 0;
}

/**
 * Mark EC signed prekey as replaced by key ID.
 *
 * Instead of immediately deleting, sets replacedAt = Date.now().
 * Replaced prekeys are excluded from normal queries but retained for
 * in-flight message decryption. Use cullReplacedEcSignedPreKeys() to
 * permanently delete after a grace period.
 *
 * @param keyId - The key ID to mark replaced
 */
export async function deleteEcSignedPreKeyByKeyId(
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const db = await getDrizzle();
  await db
    .update(ecSignedPreKeys)
    .set({ replacedAt: Date.now() })
    .where(
      and(
        eq(ecSignedPreKeys.identityType, identityType),
        eq(ecSignedPreKeys.prekeyId, keyId),
        isNull(ecSignedPreKeys.replacedAt)
      )
    );
}

/**
 * Mark all active EC signed prekeys as replaced.
 * Delegates to shared utility for DRY implementation.
 * @internal
 */
async function markAllEcSignedPreKeysReplacedInternal(
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced('ec_signed_prekeys', identityType);
}

/**
 * Mark all EC signed prekeys as replaced.
 *
 * Sets replacedAt = Date.now() on all active prekeys.
 * They are retained for in-flight message decryption and can be
 * permanently removed with cullReplacedEcSignedPreKeys().
 */
export async function deleteAllEcSignedPreKeys(identityType: IdentityType = 'aci'): Promise<void> {
  await markAllEcSignedPreKeysReplacedInternal(identityType);
}

/**
 * Get the maximum prekey ID across ALL prekeys (active + stale).
 * Used for key recovery to avoid identifier collisions (PQXDH section 4.13).
 *
 * NOTE: Intentionally includes stale prekeys -- a stale prekey still
 * occupies its ID until purged, so reusing that ID would cause a collision.
 *
 * @returns Maximum key ID or 0 if none exist
 */
export async function getMaxEcSignedPreKeyId(identityType: IdentityType = 'aci'): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ maxId: sql<number>`MAX(${ecSignedPreKeys.prekeyId})` })
    .from(ecSignedPreKeys)
    .where(eq(ecSignedPreKeys.identityType, identityType));
  return results[0]?.maxId ?? 0;
}

/**
 * Mark expired EC signed prekeys as stale outside the grace period.
 * Keeps the most recent active prekey regardless of age.
 *
 * Uses raw SQL to get actual affected row count.
 *
 * @param gracePeriodMs - Grace period in milliseconds (default: 30 days)
 * @returns Number of prekeys marked stale
 */
export async function deleteExpiredEcSignedPreKeys(
  gracePeriodMs: number = MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const rawDb = getRawDatabase();
  const cutoff = Date.now() - gracePeriodMs;
  const now = Date.now();

  // Get the most recent active prekey ID to preserve it
  const current = await getCurrentEcSignedPreKey(identityType);
  if (!current) return 0;

  // Mark expired prekeys as replaced using raw SQL to get actual count
  const result = await rawDb.runAsync(
    `UPDATE ec_signed_prekeys SET replaced_at = ?
     WHERE identity_type = ? AND created_at < ? AND prekey_id != ? AND replaced_at IS NULL`,
    [now, identityType, cutoff, current.keyId]
  );

  return result.changes ?? 0;
}

/**
 * Store an EC signed prekey, marking all existing active ones as stale.
 *
 * Marks all existing active EC signed prekeys as replaced before inserting
 * the new one. Replaced prekeys are retained for in-flight message
 * decryption and can be culled later with cullReplacedEcSignedPreKeys().
 *
 * @param prekey - The EcSignedPreKey to store
 */
export async function storeReplacingEcSignedPreKey(
  prekey: EcSignedPreKey,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Mark all existing active prekeys for this identity type as replaced
    await markAllEcSignedPreKeysReplacedInternal(identityType);
    // Insert the new one
    await prekey.save();
  });
}

/**
 * Permanently delete replaced EC signed prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 *
 * Best-effort overwrites decoded private-key bytes before deletion.
 * Delegates to shared cullReplacedPreKeys utility.
 * @param maxReplacedAgeMs - Maximum time a replaced prekey is retained before culling
 * @returns Number of culled prekeys
 */
export async function cullReplacedEcSignedPreKeys(maxReplacedAgeMs: number): Promise<number> {
  return cullReplacedPreKeys('ec_signed_prekeys', maxReplacedAgeMs);
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new EC signed prekey.
 *
 * @param params - EC signed prekey parameters
 * @param params.keyId - Unique key identifier
 * @param params.publicKey - Public key (base64 or Uint8Array)
 * @param params.privateKey - Private key (base64 or Uint8Array)
 * @param params.signature - Signature (base64 or Uint8Array)
 * @param params.timestamp - Optional timestamp (defaults to now)
 * @returns New EcSignedPreKey instance (not yet persisted)
 */
export function createEcSignedPreKey(params: {
  keyId: number;
  publicKey: string | Uint8Array;
  privateKey: string | Uint8Array;
  signature: string | Uint8Array;
  timestamp?: number;
  identityType?: IdentityType;
}): EcSignedPreKey {
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

  return new EcSignedPreKey({
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
// EcSignedPreKey Class
// ============================================================================

/**
 * EcSignedPreKey domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 * All data is stored in normalized columns (no JSON extraData).
 *
 * @example
 * ```typescript
 * // Store an EC signed prekey (replaces all existing)
 * const prekey = createEcSignedPreKey({
 *   keyId: 1,
 *   publicKey: '...',
 *   privateKey: '...',
 *   signature: '...',
 *   timestamp: Date.now(),
 * });
 * await storeReplacingEcSignedPreKey(prekey);
 *
 * // Get current EC signed prekey
 * const current = await getCurrentEcSignedPreKey();
 *
 * // Get by specific ID
 * const specific = await getEcSignedPreKeyByKeyId(keyId);
 * ```
 */
export class EcSignedPreKey {
  private readonly data: EcSignedPreKeyRow;

  constructor(row: EcSignedPreKeyRow) {
    this.data = { ...row };
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Key ID (authoritative value from prekey_id column) */
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
   * Convert to EcSignedPreKey type (for API compatibility).
   */
  toEcSignedPreKey(): {
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
   * Save EC signed prekey to database.
   */
  async save(): Promise<void> {
    const insertData: NewEcSignedPreKey = {
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
    const rawDb = (await import('../db')).getRawDatabase();
    await rawDb.runAsync(
      `INSERT INTO ec_signed_prekeys (identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
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
   * Delete EC signed prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(): Promise<void> {
    // Best-effort overwrite decoded private-key bytes before deletion.
    secureZero(this.data.privateKey);

    const db = await getDrizzle();
    await db
      .delete(ecSignedPreKeys)
      .where(
        and(
          eq(ecSignedPreKeys.identityType, this.data.identityType),
          eq(ecSignedPreKeys.prekeyId, this.data.prekeyId)
        )
      );
  }
}
