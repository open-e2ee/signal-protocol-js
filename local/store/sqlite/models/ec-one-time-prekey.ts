/**
 * EcOneTimePreKey Model
 *
 * Domain model for Signal Protocol EC one-time prekeys.
 * EC one-time prekeys are single-use keys consumed during session establishment.
 */

import type { SqliteExecutor } from '../driver';
import { EC_ONE_TIME_PREKEY_COLUMNS, placeholders, type EcOneTimePreKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import { asBase64 } from '../../../../types/utils';
import type { IdentityType } from '../../../../keys/types';
import { markPreKeysReplaced, cullReplacedPreKeys } from './replaced-prekeys';

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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<EcOneTimePreKey | null> {
  const row = await db.first<EcOneTimePreKeyRow>(
    `SELECT ${EC_ONE_TIME_PREKEY_COLUMNS} FROM ec_one_time_prekeys
     WHERE identity_type = ? AND prekey_id = ? LIMIT 1`,
    [identityType, keyId]
  );
  return row ? new EcOneTimePreKey(row) : null;
}

/**
 * Get all EC one-time prekeys.
 *
 * @returns Array of all EcOneTimePreKey instances
 */
export async function getAllEcOneTimePreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<EcOneTimePreKey[]> {
  const rows = await db.all<EcOneTimePreKeyRow>(
    `SELECT ${EC_ONE_TIME_PREKEY_COLUMNS} FROM ec_one_time_prekeys WHERE identity_type = ?`,
    [identityType]
  );
  return rows.map((row) => new EcOneTimePreKey(row));
}

/**
 * Count EC one-time prekeys.
 *
 * @returns Number of EC one-time prekeys
 */
export async function countEcOneTimePreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number> {
  const row = await db.first<{ count: number }>(
    'SELECT COUNT(*) AS count FROM ec_one_time_prekeys WHERE identity_type = ?',
    [identityType]
  );
  return row?.count ?? 0;
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
  db: SqliteExecutor,
  keyId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.transaction(async (tx) => {
    // Fetch the prekey to overwrite decoded private-key bytes where possible.
    const prekey = await getEcOneTimePreKeyByKeyId(tx, keyId, identityType);
    if (prekey) {
      secureZero(prekey.privateKey);
    }

    await tx.run('DELETE FROM ec_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      identityType,
      keyId,
    ]);
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
      `SELECT private_key AS privateKey FROM ec_one_time_prekeys ${where}`,
      params
    );
    for (const row of rows) {
      secureZero(row.privateKey);
    }

    await tx.run(`DELETE FROM ec_one_time_prekeys ${where}`, params);
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
export async function deleteAllEcOneTimePreKeys(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.transaction(async (tx) => {
    // Fetch prekeys to overwrite decoded private-key bytes where possible.
    const all = await getAllEcOneTimePreKeys(tx, identityType);
    for (const prekey of all) {
      secureZero(prekey.privateKey);
    }

    await tx.run('DELETE FROM ec_one_time_prekeys WHERE identity_type = ?', [identityType]);
  });
}

/**
 * Store a batch of EC one-time prekeys.
 *
 * @param prekeys - Array of EcOneTimePreKey instances to store
 */
export async function storeBatchEcOneTimePreKeys(
  db: SqliteExecutor,
  prekeys: EcOneTimePreKey[]
): Promise<void> {
  if (prekeys.length === 0) return;

  await db.transaction(async (tx) => {
    for (const pk of prekeys) {
      await pk.save(tx);
    }
  });
}

/**
 * Mark all active EC one-time prekeys as replaced.
 * Called before generating new EC one-time prekeys.
 * @param identityType - 'aci' or 'pni'
 */
export async function markAllEcOneTimePreKeysReplaced(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await markPreKeysReplaced(db, 'ec_one_time_prekeys', identityType);
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
  db: SqliteExecutor,
  maxReplacedAgeMs: number,
  identityType: IdentityType = 'aci'
): Promise<number> {
  return cullReplacedPreKeys(db, 'ec_one_time_prekeys', maxReplacedAgeMs, identityType);
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
    typeof params.publicKey === 'string' ? params.publicKey : bytesToBase64(params.publicKey);
  const privateKey =
    typeof params.privateKey === 'string' ? params.privateKey : bytesToBase64(params.privateKey);

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
 * @example
 * ```typescript
 * // Store batch of EC one-time prekeys
 * const prekeys = [
 *   createEcOneTimePreKey({ keyId: 1, publicKey: '...', privateKey: '...' }),
 *   createEcOneTimePreKey({ keyId: 2, publicKey: '...', privateKey: '...' }),
 * ];
 * await storeBatchEcOneTimePreKeys(db, prekeys);
 *
 * // Get all prekeys
 * const all = await getAllEcOneTimePreKeys(db);
 *
 * // Remove consumed prekey
 * await deleteEcOneTimePreKeyByKeyId(db, 1);
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
  async save(db: SqliteExecutor): Promise<void> {
    // Plain insert. The unique index (identity_type, prekey_id) rejects a
    // reused ID: a conflict is a defect in the caller's ID sequence, and an
    // overwrite would replace a private key that a peer may still address.
    await db.run(
      `INSERT INTO ec_one_time_prekeys (identity_type, prekey_id, public_key, private_key, created_at, replaced_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        this.data.identityType,
        this.data.prekeyId,
        this.data.publicKey,
        this.data.privateKey,
        this.data.createdAt,
        this.data.replacedAt ?? null,
      ]
    );
  }

  /**
   * Delete EC one-time prekey from database.
   * Best-effort overwrites decoded private-key bytes before deletion.
   */
  async delete(db: SqliteExecutor): Promise<void> {
    secureZero(this.data.privateKey);

    await db.run('DELETE FROM ec_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?', [
      this.data.identityType,
      this.data.prekeyId,
    ]);
  }
}
