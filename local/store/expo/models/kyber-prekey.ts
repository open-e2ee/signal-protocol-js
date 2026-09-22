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
import type { IdentityType, KyberPreKey as KyberPreKeyType } from '../../../../keys/types';
import {
  assertUnambiguousKyberPreKeyStore,
  createKyberPreKeyInstanceId,
} from '../../kyber-prekey-lifecycle';
import { markPreKeysReplaced } from './replaced-prekey-utils';

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
    .where(and(eq(kyberPreKeys.identityType, identityType), eq(kyberPreKeys.prekeyId, keyId)))
    .limit(1);

  return results.length > 0 ? new KyberPreKey(results[0]) : null;
}

/**
 * Get the current (latest) Kyber prekey.
 *
 * Returns the one unreplaced prekey for the identity. Key IDs are identifiers,
 * not an ordering signal.
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
    .orderBy(desc(kyberPreKeys.createdAt), desc(kyberPreKeys.id))
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
 * NOTE: Intentionally includes stale prekeys. A stale prekey still
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
 * @param maxReplacedAgeMs - Maximum time a replaced prekey is retained before culling
 * @returns Number of culled prekeys
 */
export async function cullReplacedKyberPreKeys(maxReplacedAgeMs: number): Promise<number> {
  const rawDb = getRawDatabase();
  const now = Date.now();
  const pastCutoff = now - maxReplacedAgeMs;
  const futureCutoff = now + maxReplacedAgeMs;
  let culledCount = 0;

  await rawDb.withTransactionAsync(async () => {
    const rows = await rawDb.getAllAsync<{ id: number; private_key: string }>(
      `SELECT id, private_key FROM kyber_prekeys
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)`,
      [pastCutoff, futureCutoff]
    );
    if (rows.length === 0) return;
    for (const row of rows) secureZero(row.private_key);

    const placeholders = rows.map(() => '?').join(', ');
    const rowIds = rows.map((row) => row.id);
    // Delete by the immutable parent row ID. The schema FK also cascades this
    // deletion when foreign-key enforcement is enabled by the host database.
    await rawDb.runAsync(
      `DELETE FROM kyber_prekey_used WHERE kyber_prekey_row_id IN (${placeholders})`,
      rowIds
    );
    const result = await rawDb.runAsync(
      `DELETE FROM kyber_prekeys
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)`,
      [pastCutoff, futureCutoff]
    );
    culledCount = result.changes ?? 0;
  });
  return culledCount;
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
    instanceId: '',
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

  /** Store-generated identity for this immutable retained instance. */
  get instanceId(): string {
    return this.data.instanceId;
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
    const instanceId = this.data.instanceId || (await createKyberPreKeyInstanceId());
    const insertData: NewKyberPreKey = {
      instanceId,
      identityType: this.data.identityType,
      prekeyId: this.data.prekeyId,
      publicKey: this.data.publicKey,
      privateKey: this.data.privateKey,
      signature: this.data.signature,
      timestamp: this.data.timestamp,
      createdAt: this.data.createdAt,
      replacedAt: this.data.replacedAt ?? null,
    };

    const rawDb = getRawDatabase();
    const identityType = (insertData.identityType ?? 'aci') as IdentityType;
    await rawDb.withTransactionAsync(async () => {
      const existing = await rawDb.getFirstAsync<{
        instanceId: string;
        publicKey: string;
        privateKey: string;
        signature: string | null;
        timestamp: number;
      }>(
        `SELECT instance_id AS instanceId, public_key AS publicKey,
                private_key AS privateKey, signature, timestamp
         FROM kyber_prekeys WHERE identity_type = ? AND prekey_id = ?`,
        [identityType, insertData.prekeyId]
      );
      if (existing) {
        assertUnambiguousKyberPreKeyStore(
          {
            keyId: insertData.prekeyId,
            publicKey: existing.publicKey,
            privateKey: existing.privateKey,
            signature: existing.signature ?? '',
            timestamp: existing.timestamp,
          } as KyberPreKeyType,
          this.toKyberPreKey() as KyberPreKeyType,
          identityType
        );
        this.data.instanceId = existing.instanceId;
        return;
      }
      await rawDb.runAsync(
        `UPDATE kyber_prekeys SET replaced_at = ?
         WHERE identity_type = ? AND replaced_at IS NULL`,
        [Date.now(), identityType]
      );
      await rawDb.runAsync(
        `INSERT INTO kyber_prekeys (instance_id, identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          insertData.instanceId,
          identityType,
          insertData.prekeyId,
          insertData.publicKey,
          insertData.privateKey,
          insertData.signature ?? null,
          insertData.timestamp,
          insertData.createdAt,
          insertData.replacedAt ?? null,
        ]
      );
      this.data.instanceId = instanceId;
    });
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
