/**
 * EcSignedPreKey Model
 *
 * Domain model for Signal Protocol EC signed prekeys.
 * EC signed prekeys are medium-term keys rotated weekly.
 *
 * Schema (fully normalized, no JSON blobs):
 * - Uses prekey_id column as the authoritative keyId
 * - Uses timestamp column for logical key creation time
 */

import type { SqliteExecutor } from '../driver';
import { EC_SIGNED_PREKEY_COLUMNS, type EcSignedPreKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import { asBase64 } from '../../../../types/utils';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../../types/protocol-config';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekeys';

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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey | null> {
  const row = await db.first<EcSignedPreKeyRow>(
    `SELECT ${EC_SIGNED_PREKEY_COLUMNS} FROM ec_signed_prekeys
     WHERE identity_type = ? AND prekey_id = ? AND replaced_at IS NULL LIMIT 1`,
    [identityType, keyId]
  );
  return row ? new EcSignedPreKey(row) : null;
}

/**
 * Get the current (most recent) EC signed prekey.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Current EcSignedPreKey or null if none exists
 */
export async function getCurrentEcSignedPreKey(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey | null> {
  const row = await db.first<EcSignedPreKeyRow>(
    `SELECT ${EC_SIGNED_PREKEY_COLUMNS} FROM ec_signed_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL
     ORDER BY created_at DESC, prekey_id DESC LIMIT 1`,
    [identityType]
  );
  return row ? new EcSignedPreKey(row) : null;
}

/**
 * Get all EC signed prekeys.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Array of all EcSignedPreKey instances
 */
export async function getAllEcSignedPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<EcSignedPreKey[]> {
  const rows = await db.all<EcSignedPreKeyRow>(
    `SELECT ${EC_SIGNED_PREKEY_COLUMNS} FROM ec_signed_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL ORDER BY created_at DESC`,
    [identityType]
  );
  return rows.map((row) => new EcSignedPreKey(row));
}

/**
 * Count EC signed prekeys.
 *
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns Number of EC signed prekeys
 */
export async function countEcSignedPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ count: number }>(
    `SELECT COUNT(*) AS count FROM ec_signed_prekeys
     WHERE identity_type = ? AND replaced_at IS NULL`,
    [identityType]
  );
  return row?.count ?? 0;
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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.run(
    `UPDATE ec_signed_prekeys SET replaced_at = ?
     WHERE identity_type = ? AND prekey_id = ? AND replaced_at IS NULL`,
    [Date.now(), identityType, keyId]
  );
}

/**
 * Mark all EC signed prekeys as replaced.
 *
 * Sets replacedAt = Date.now() on all active prekeys.
 * They are retained for in-flight message decryption and can be
 * permanently removed with cullReplacedEcSignedPreKeys().
 */
export async function deleteAllEcSignedPreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced(db, 'ec_signed_prekeys', identityType);
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
export async function getMaxEcSignedPreKeyId(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ maxId: number | null }>(
    'SELECT MAX(prekey_id) AS maxId FROM ec_signed_prekeys WHERE identity_type = ?',
    [identityType]
  );
  return row?.maxId ?? 0;
}

/**
 * Mark expired EC signed prekeys as stale outside the grace period.
 * Keeps the most recent active prekey regardless of age.
 *
 * @param gracePeriodMs - Grace period in milliseconds (default: 30 days)
 * @returns Number of prekeys marked stale
 */
export async function deleteExpiredEcSignedPreKeys(
  db: SqliteExecutor,
  gracePeriodMs: number = MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const cutoff = Date.now() - gracePeriodMs;
  const now = Date.now();

  // Get the most recent active prekey ID to preserve it
  const current = await getCurrentEcSignedPreKey(db, identityType);
  if (!current) return 0;

  return db.run(
    `UPDATE ec_signed_prekeys SET replaced_at = ?
     WHERE identity_type = ? AND created_at < ? AND prekey_id != ? AND replaced_at IS NULL`,
    [now, identityType, cutoff, current.keyId]
  );
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
  db: SqliteExecutor,
  prekey: EcSignedPreKey,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.transaction(async (tx) => {
    // Mark all existing active prekeys for this identity type as replaced
    await markPreKeysReplaced(tx, 'ec_signed_prekeys', identityType);
    // Insert the new one
    await prekey.save(tx);
  });
}

/**
 * Permanently delete replaced EC signed prekeys older than maxReplacedAgeMs.
 * Also deletes keys with replacedAt far in the future (clock-skew protection).
 *
 * Best-effort overwrites decoded private-key bytes before deletion.
 * @param maxReplacedAgeMs - Maximum time a replaced prekey is retained before culling
 * @returns Number of culled prekeys
 */
export async function cullReplacedEcSignedPreKeys(
  db: SqliteExecutor,
  maxReplacedAgeMs: number
): Promise<number> {
  return cullReplacedPreKeys(db, 'ec_signed_prekeys', maxReplacedAgeMs);
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
    typeof params.publicKey === 'string' ? params.publicKey : bytesToBase64(params.publicKey);
  const privateKey =
    typeof params.privateKey === 'string' ? params.privateKey : bytesToBase64(params.privateKey);
  const signature =
    typeof params.signature === 'string' ? params.signature : bytesToBase64(params.signature);

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
 * await storeReplacingEcSignedPreKey(db, prekey);
 *
 * // Get current EC signed prekey
 * const current = await getCurrentEcSignedPreKey(db);
 *
 * // Get by specific ID
 * const specific = await getEcSignedPreKeyByKeyId(db, keyId);
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

  /** Signature (base64 encoded) */
  get signature(): string {
    return this.data.signature;
  }

  /** Signature as Uint8Array */
  get signatureBytes(): Uint8Array {
    return base64ToBytes(asBase64(this.data.signature));
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
   *
   * The upsert on (identity_type, prekey_id) overwrites the private key of a
   * row with the same key ID. Best-effort overwrites the decoded bytes of that
   * old private key first, in the same transaction.
   */
  async save(db: SqliteExecutor): Promise<void> {
    await db.transaction(async (tx) => {
      const existing = await tx.first<{ privateKey: string }>(
        `SELECT private_key AS privateKey FROM ec_signed_prekeys
         WHERE identity_type = ? AND prekey_id = ?`,
        [this.data.identityType, this.data.prekeyId]
      );
      if (existing) secureZero(existing.privateKey);

      await tx.run(
        `INSERT INTO ec_signed_prekeys (identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (identity_type, prekey_id) DO UPDATE SET
           public_key = excluded.public_key,
           private_key = excluded.private_key,
           signature = excluded.signature,
           timestamp = excluded.timestamp,
           created_at = excluded.created_at,
           replaced_at = excluded.replaced_at`,
        [
          this.data.identityType,
          this.data.prekeyId,
          this.data.publicKey,
          this.data.privateKey,
          this.data.signature,
          this.data.timestamp,
          this.data.createdAt,
          this.data.replacedAt ?? null,
        ]
      );
    });
  }

  /**
   * Delete EC signed prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(db: SqliteExecutor): Promise<void> {
    secureZero(this.data.privateKey);

    await db.run('DELETE FROM ec_signed_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      this.data.identityType,
      this.data.prekeyId,
    ]);
  }
}
