/**
 * KyberOneTimePreKey Model
 *
 * Domain model for PQXDH Kyber one-time prekeys.
 * Kyber one-time prekeys are consumed on use, providing per-session
 * post-quantum forward secrecy.
 *
 * Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys.
 *
 * Schema (fully normalized, no JSON blobs):
 * - Uses prekey_id column as the authoritative keyId
 * - Uses timestamp column for logical key creation time
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import type { SqliteExecutor } from '../driver';
import { KYBER_ONE_TIME_PREKEY_COLUMNS, placeholders, type KyberOneTimePreKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import { asBase64 } from '../../../../types/utils';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekeys';

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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<KyberOneTimePreKey | null> {
  const row = await db.first<KyberOneTimePreKeyRow>(
    `SELECT ${KYBER_ONE_TIME_PREKEY_COLUMNS} FROM kyber_one_time_prekeys
     WHERE identity_type = ? AND prekey_id = ? LIMIT 1`,
    [identityType, keyId]
  );
  return row ? new KyberOneTimePreKey(row) : null;
}

/**
 * Get all Kyber one-time prekeys.
 *
 * @returns Array of all KyberOneTimePreKey instances
 */
export async function getAllKyberOneTimePreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<KyberOneTimePreKey[]> {
  const rows = await db.all<KyberOneTimePreKeyRow>(
    `SELECT ${KYBER_ONE_TIME_PREKEY_COLUMNS} FROM kyber_one_time_prekeys WHERE identity_type = ?`,
    [identityType]
  );
  return rows.map((row) => new KyberOneTimePreKey(row));
}

/**
 * Count Kyber one-time prekeys.
 *
 * @returns Number of Kyber one-time prekeys
 */
export async function countKyberOneTimePreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ count: number }>(
    'SELECT COUNT(*) AS count FROM kyber_one_time_prekeys WHERE identity_type = ?',
    [identityType]
  );
  return row?.count ?? 0;
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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.transaction(async (tx) => {
    // Fetch the prekey to overwrite decoded private-key bytes where possible.
    const prekey = await getKyberOneTimePreKeyByKeyId(tx, keyId, identityType);
    if (prekey) {
      secureZero(prekey.privateKey);
    }

    await tx.run('DELETE FROM kyber_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      identityType,
      keyId,
    ]);
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
  db: SqliteExecutor,
  keyIds: number[],
  identityType: IdentityType = 'aci'
): Promise<void> {
  if (keyIds.length === 0) return;

  const where = `WHERE identity_type = ? AND prekey_id IN (${placeholders(keyIds.length)})`;
  const params = [identityType, ...keyIds];

  await db.transaction(async (tx) => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const rows = await tx.all<{ privateKey: string }>(
      `SELECT private_key AS privateKey FROM kyber_one_time_prekeys ${where}`,
      params
    );
    for (const row of rows) {
      secureZero(row.privateKey);
    }

    await tx.run(`DELETE FROM kyber_one_time_prekeys ${where}`, params);
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
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.transaction(async (tx) => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const all = await getAllKyberOneTimePreKeys(tx, identityType);
    for (const prekey of all) {
      secureZero(prekey.privateKey);
    }

    await tx.run('DELETE FROM kyber_one_time_prekeys WHERE identity_type = ?', [identityType]);
  });
}

/**
 * Store a batch of Kyber one-time prekeys.
 *
 * @param prekeys - Array of KyberOneTimePreKey instances to store
 */
export async function storeBatchKyberOneTimePreKeys(
  db: SqliteExecutor,
  prekeys: KyberOneTimePreKey[]
): Promise<void> {
  if (prekeys.length === 0) return;

  await db.transaction(async (tx) => {
    for (const pk of prekeys) {
      await pk.save(tx);
    }
  });
}

/**
 * Mark all active Kyber one-time prekeys as replaced.
 * Called before generating new Kyber one-time prekeys.
 * @param identityType - 'aci' or 'pni'
 */
export async function markAllKyberOneTimePreKeysReplaced(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced(db, 'kyber_one_time_prekeys', identityType);
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
  db: SqliteExecutor,
  maxReplacedAgeMs: number,
  identityType: IdentityType = 'aci'
): Promise<number> {
  return cullReplacedPreKeys(db, 'kyber_one_time_prekeys', maxReplacedAgeMs, identityType);
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
    typeof params.publicKey === 'string' ? params.publicKey : bytesToBase64(params.publicKey);
  const privateKey =
    typeof params.privateKey === 'string' ? params.privateKey : bytesToBase64(params.privateKey);
  const signature =
    typeof params.signature === 'string' ? params.signature : bytesToBase64(params.signature);

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
 * All data is stored in normalized columns (no JSON extraData).
 *
 * @example
 * ```typescript
 * // Store batch of Kyber one-time prekeys
 * const prekeys = [
 *   createKyberOneTimePreKey({ keyId: 1, publicKey: '...', privateKey: '...', signature: '...' }),
 *   createKyberOneTimePreKey({ keyId: 2, publicKey: '...', privateKey: '...', signature: '...' }),
 * ];
 * await storeBatchKyberOneTimePreKeys(db, prekeys);
 *
 * // Get specific prekey for decapsulation
 * const prekey = await getKyberOneTimePreKeyByKeyId(db, 1);
 *
 * // Remove consumed prekey (CRITICAL for forward secrecy)
 * await deleteKyberOneTimePreKeyByKeyId(db, 1);
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
  async save(db: SqliteExecutor): Promise<void> {
    // Plain insert. The unique index (identity_type, prekey_id) rejects a
    // reused ID: a conflict is a defect in the caller's ID sequence, and an
    // overwrite would replace a private key that a peer may still address.
    await db.run(
      `INSERT INTO kyber_one_time_prekeys (identity_type, prekey_id, public_key, private_key, signature, timestamp, created_at, replaced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
  }

  /**
   * Delete Kyber one-time prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   *
   * CRITICAL: Must be called immediately after successful decapsulation
   * to provide per-session post-quantum forward secrecy.
   */
  async delete(db: SqliteExecutor): Promise<void> {
    secureZero(this.data.privateKey);

    await db.run('DELETE FROM kyber_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      this.data.identityType,
      this.data.prekeyId,
    ]);
  }
}
