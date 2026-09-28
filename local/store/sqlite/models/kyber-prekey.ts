/**
 * KyberPreKey Model
 *
 * Domain model for PQXDH Kyber prekeys.
 * Kyber prekeys provide post-quantum resistance using CRYSTALS-Kyber-1024.
 *
 * These are "last-resort" signed prekeys that persist until rotated.
 *
 * Schema (fully normalized, no JSON blobs):
 * - Uses prekey_id column as the authoritative keyId
 * - Uses timestamp column for logical key creation time
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import type { SqliteExecutor } from '../driver';
import { KYBER_PREKEY_COLUMNS, placeholders, type KyberPreKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import { asBase64 } from '../../../../types/utils';
import type { IdentityType, KyberPreKey as KyberPreKeyType } from '../../../../keys/types';
import {
  assertUnambiguousKyberPreKeyStore,
  createKyberPreKeyInstanceId,
} from '../../kyber-prekey-lifecycle';
import { markPreKeysReplaced } from './replaced-prekeys';

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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey | null> {
  const row = await db.first<KyberPreKeyRow>(
    `SELECT ${KYBER_PREKEY_COLUMNS} FROM kyber_prekeys
     WHERE identity_type = ? AND prekey_id = ? LIMIT 1`,
    [identityType, keyId]
  );
  return row ? new KyberPreKey(row) : null;
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
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey | null> {
  const row = await db.first<KyberPreKeyRow>(
    `SELECT ${KYBER_PREKEY_COLUMNS} FROM kyber_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL
     ORDER BY created_at DESC, id DESC LIMIT 1`,
    [identityType]
  );
  return row ? new KyberPreKey(row) : null;
}

/**
 * Get all Kyber prekeys.
 *
 * @returns Array of all KyberPreKey instances
 */
export async function getAllKyberPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<KyberPreKey[]> {
  const rows = await db.all<KyberPreKeyRow>(
    `SELECT ${KYBER_PREKEY_COLUMNS} FROM kyber_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL`,
    [identityType]
  );
  return rows.map((row) => new KyberPreKey(row));
}

/**
 * Count Kyber prekeys.
 *
 * @returns Number of Kyber prekeys
 */
export async function countKyberPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ count: number }>(
    `SELECT COUNT(*) AS count FROM kyber_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL`,
    [identityType]
  );
  return row?.count ?? 0;
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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.run(
    `UPDATE kyber_prekeys SET replaced_at = ?
     WHERE identity_type = ? AND prekey_id = ? AND replaced_at IS NULL`,
    [Date.now(), identityType, keyId]
  );
}

/**
 * Mark all Kyber prekeys as replaced.
 *
 * Sets replacedAt = Date.now() on all active prekeys.
 * They are retained for in-flight message decryption and can be
 * permanently removed with cullReplacedKyberPreKeys().
 */
export async function deleteAllKyberPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced(db, 'kyber_prekeys', identityType);
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
export async function getMaxKyberPreKeyId(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ maxId: number | null }>(
    'SELECT MAX(prekey_id) AS maxId FROM kyber_prekeys WHERE identity_type = ?',
    [identityType]
  );
  return row?.maxId ?? 0;
}

/**
 * Permanently delete replaced Kyber prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 *
 * Best-effort overwrites decoded private-key bytes before deletion.
 * @param maxReplacedAgeMs - Maximum time a replaced prekey is retained before culling
 * @returns Number of culled prekeys
 */
export async function cullReplacedKyberPreKeys(
  db: SqliteExecutor,
  maxReplacedAgeMs: number
): Promise<number> {
  const now = Date.now();
  const pastCutoff = now - maxReplacedAgeMs;
  const futureCutoff = now + maxReplacedAgeMs;

  return db.transaction(async (tx) => {
    const rows = await tx.all<{ id: number; privateKey: string }>(
      `SELECT id, private_key AS privateKey FROM kyber_prekeys
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)`,
      [pastCutoff, futureCutoff]
    );
    if (rows.length === 0) return 0;
    for (const row of rows) secureZero(row.privateKey);

    // Delete by the immutable parent row ID. The schema FK also cascades this
    // deletion when foreign-key enforcement is enabled by the host database.
    await tx.run(
      `DELETE FROM kyber_prekey_used WHERE kyber_prekey_row_id IN (${placeholders(rows.length)})`,
      rows.map((row) => row.id)
    );
    return tx.run(
      `DELETE FROM kyber_prekeys
       WHERE replaced_at IS NOT NULL AND (replaced_at < ? OR replaced_at > ?)`,
      [pastCutoff, futureCutoff]
    );
  });
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
    typeof params.publicKey === 'string' ? params.publicKey : bytesToBase64(params.publicKey);
  const privateKey =
    typeof params.privateKey === 'string' ? params.privateKey : bytesToBase64(params.privateKey);
  const signature = params.signature
    ? typeof params.signature === 'string'
      ? params.signature
      : bytesToBase64(params.signature)
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
 * await kyber.save(db);
 *
 * // Get current Kyber prekey
 * const current = await getCurrentKyberPreKey(db);
 *
 * // Delete by ID
 * await deleteKyberPreKeyByKeyId(db, 1);
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
    return base64ToBytes(asBase64(this.data.publicKey));
  }

  /** Private key (base64 encoded) */
  get privateKey(): string {
    return this.data.privateKey;
  }

  /** Private key as Uint8Array */
  get privateKeyBytes(): Uint8Array {
    return base64ToBytes(asBase64(this.data.privateKey));
  }

  /** Signature (base64 encoded), may be null */
  get signature(): string | null {
    return this.data.signature;
  }

  /** Signature as Uint8Array, may be null */
  get signatureBytes(): Uint8Array | null {
    return this.data.signature ? base64ToBytes(asBase64(this.data.signature)) : null;
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
  async save(db: SqliteExecutor): Promise<void> {
    const instanceId = this.data.instanceId || (await createKyberPreKeyInstanceId());
    const identityType = this.data.identityType as IdentityType;
    await db.transaction(async (tx) => {
      const existing = await tx.first<{
        instanceId: string;
        publicKey: string;
        privateKey: string;
        signature: string | null;
        timestamp: number;
      }>(
        `SELECT instance_id AS instanceId, public_key AS publicKey,
                private_key AS privateKey, signature, timestamp
         FROM kyber_prekeys WHERE identity_type = ? AND prekey_id = ?`,
        [identityType, this.data.prekeyId]
      );
      if (existing) {
        assertUnambiguousKyberPreKeyStore(
          {
            keyId: this.data.prekeyId,
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
      await tx.run(
        `UPDATE kyber_prekeys SET replaced_at = ?
         WHERE identity_type = ? AND replaced_at IS NULL`,
        [Date.now(), identityType]
      );
      await tx.run(
        `INSERT INTO kyber_prekeys (instance_id, identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          instanceId,
          identityType,
          this.data.prekeyId,
          this.data.publicKey,
          this.data.privateKey,
          this.data.signature ?? null,
          this.data.timestamp,
          this.data.createdAt,
          this.data.replacedAt ?? null,
        ]
      );
      this.data.instanceId = instanceId;
    });
  }

  /**
   * Delete Kyber prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(db: SqliteExecutor): Promise<void> {
    secureZero(this.data.privateKey);

    await db.run('DELETE FROM kyber_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      this.data.identityType,
      this.data.prekeyId,
    ]);
  }
}
