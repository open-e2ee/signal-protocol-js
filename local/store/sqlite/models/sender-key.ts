/**
 * SenderKey Model
 *
 * Domain model for Signal Protocol Sender Keys.
 * Sender Keys enable efficient O(1) group encryption.
 *
 * A row is the whole `SenderKeyState[]` record for one (group, sender, device)
 * triple, serialized into the `record` column. Current state comes first, then
 * the superseded states the rotation window still needs. Primary key:
 * (groupId, senderId, deviceId).
 *
 * The chain keys and the sender's private signature key are in that column.
 * They stay on the device. The database file is SQLCipher-encrypted with an
 * application-supplied key, and this material is never sent to a server.
 */

import type { SenderKeyState } from '../../../../internal/protocol/sender-keys/manager';
import type { SqliteExecutor } from '../driver';
import { SENDER_KEY_COLUMNS, type SenderKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';

// ============================================================================
// Types
// ============================================================================

/**
 * Persisted sender key record for group messaging.
 *
 * Note: Uses plain strings (not branded Base64) because this data is
 * serialized/deserialized from SQLite.
 */
export interface StoredSenderKey {
  groupId: string;
  senderId: string;
  deviceId: number;
  /** JSON-serialized `SenderKeyState[]`, current state first */
  record: string;
  createdAt: number;
  updatedAt: number;
}

/**
 * Parse a `record` column into states.
 *
 * A truncated or corrupted column degrades to an empty record rather than
 * throwing: the caller treats that as "no sender key", which triggers a
 * distribution-message request. Throwing would strand the group instead.
 */
export function parseSenderKeyRecord(record: string): SenderKeyState[] {
  try {
    const parsed = JSON.parse(record);
    return Array.isArray(parsed) ? (parsed as SenderKeyState[]) : [];
  } catch {
    return [];
  }
}

/** Zero every chain key and signature key held in a parsed record. */
function zeroStates(states: SenderKeyState[]): void {
  for (const state of states) {
    if (state.chainKey) secureZero(state.chainKey);
    if (state.signatureKey) secureZero(state.signatureKey);
  }
}

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get sender key record by group, sender, and device.
 *
 * @param groupId - Group identifier
 * @param senderId - Sender identifier
 * @param deviceId - Device identifier
 * @returns SenderKey instance or null if not found
 */
export async function getSenderKey(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  deviceId: number
): Promise<SenderKey | null> {
  const row = await db.first<SenderKeyRow>(
    `SELECT ${SENDER_KEY_COLUMNS} FROM sender_keys
     WHERE group_id = ? AND sender_id = ? AND device_id = ? LIMIT 1`,
    [groupId, senderId, deviceId]
  );

  return row ? new SenderKey(row) : null;
}

/**
 * Get all sender key records for a group.
 *
 * @param groupId - Group identifier
 * @returns Array of SenderKey instances
 */
export async function getSenderKeysByGroup(
  db: SqliteExecutor,
  groupId: string
): Promise<SenderKey[]> {
  const results = await db.all<SenderKeyRow>(
    `SELECT ${SENDER_KEY_COLUMNS} FROM sender_keys WHERE group_id = ?`,
    [groupId]
  );

  return results.map((row) => new SenderKey(row));
}

/**
 * Find the group whose sender key record contains an id, for one sender device.
 *
 * A received group message names its sender key by an opaque `senderKeyId`,
 * and carries no group. This is the receiver's only route back to a group.
 *
 * The lookup is a scan of that sender device's records rather than an index on
 * the id. Records here are stored as plaintext JSON, because SQLCipher
 * encrypts the file and not the row. A scan therefore reads them directly,
 * bounded by the groups shared with that one device. Indexing the ids would
 * mean a second
 * table that can disagree with the records it points at. The correctness that
 * buys back is worth more than the lookup it saves.
 *
 * Superseded states count as matches. A message encrypted just before a
 * rotation is still in flight when the rotation lands and names the key the
 * rotation replaced.
 *
 * @param senderKeyId - Opaque identifier read from the SenderKeyMessage frame
 * @param senderId - Sender identifier, from the envelope
 * @param deviceId - Sender device identifier, from the envelope
 * @returns The group identifier, or null if this device holds no such key
 */
export async function findGroupBySenderKeyId(
  db: SqliteExecutor,
  senderKeyId: string,
  senderId: string,
  deviceId: number
): Promise<string | null> {
  if (!senderKeyId) return null;

  const results = await db.all<{ groupId: string; record: string }>(
    'SELECT group_id AS groupId, record FROM sender_keys WHERE sender_id = ? AND device_id = ?',
    [senderId, deviceId]
  );

  for (const row of results) {
    const states = parseSenderKeyRecord(row.record);
    if (states.some((state) => state.senderKeyId === senderKeyId)) {
      return row.groupId;
    }
  }

  return null;
}

/**
 * Get all sender key records for a sender.
 *
 * @param senderId - Sender identifier
 * @returns Array of SenderKey instances
 */
export async function getSenderKeysBySender(
  db: SqliteExecutor,
  senderId: string
): Promise<SenderKey[]> {
  const results = await db.all<SenderKeyRow>(
    `SELECT ${SENDER_KEY_COLUMNS} FROM sender_keys WHERE sender_id = ?`,
    [senderId]
  );

  return results.map((row) => new SenderKey(row));
}

/**
 * Count all sender key records.
 *
 * @returns Number of sender key records
 */
export async function countSenderKeys(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ count: number }>('SELECT COUNT(*) AS count FROM sender_keys');
  return row?.count ?? 0;
}

/**
 * Count sender key records for a group.
 *
 * @param groupId - Group identifier
 * @returns Number of sender key records for the group
 */
export async function countSenderKeysByGroup(
  db: SqliteExecutor,
  groupId: string
): Promise<number> {
  const row = await db.first<{ count: number }>(
    'SELECT COUNT(*) AS count FROM sender_keys WHERE group_id = ?',
    [groupId]
  );
  return row?.count ?? 0;
}

/**
 * Delete a sender key record by group, sender, and device.
 * Securely zeros chain and signature keys before deletion (Section 8.1).
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param groupId - Group identifier
 * @param senderId - Sender identifier
 * @param deviceId - Device identifier
 */
export async function deleteSenderKey(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  deviceId: number
): Promise<void> {
  await db.transaction(async (tx) => {
    const senderKey = await getSenderKey(tx, groupId, senderId, deviceId);
    if (senderKey) {
      zeroStates(senderKey.states);
    }

    await tx.run('DELETE FROM sender_keys WHERE group_id = ? AND sender_id = ? AND device_id = ?', [
      groupId,
      senderId,
      deviceId,
    ]);
  });
}

/**
 * Delete all sender key records for a group, and the group's skipped message
 * keys with them. A skipped key left behind would still decrypt its message
 * after the group is gone.
 * Securely zeros chain and signature keys before deletion (Section 8.1).
 * Called when leaving a group or when group is deleted.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param groupId - Group identifier
 * @returns Number of records deleted
 */
export async function deleteSenderKeysByGroup(
  db: SqliteExecutor,
  groupId: string
): Promise<number> {
  return db.transaction(async (tx) => {
    const groupKeys = await getSenderKeysByGroup(tx, groupId);
    for (const senderKey of groupKeys) {
      zeroStates(senderKey.states);
    }

    await tx.run('DELETE FROM sender_keys WHERE group_id = ?', [groupId]);
    await tx.run('DELETE FROM skipped_sender_keys WHERE group_id = ?', [groupId]);
    return groupKeys.length;
  });
}

/**
 * Delete all sender key records for a sender.
 * Securely zeros chain and signature keys before deletion (Section 8.1).
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param senderId - Sender identifier
 */
export async function deleteSenderKeysBySender(
  db: SqliteExecutor,
  senderId: string
): Promise<void> {
  await db.transaction(async (tx) => {
    const senderKeysList = await getSenderKeysBySender(tx, senderId);
    for (const senderKey of senderKeysList) {
      zeroStates(senderKey.states);
    }

    await tx.run('DELETE FROM sender_keys WHERE sender_id = ?', [senderId]);
  });
}

/**
 * Delete all sender key records.
 * Securely zeros chain and signature keys before deletion (Section 8.1).
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 */
export async function deleteAllSenderKeys(db: SqliteExecutor): Promise<void> {
  await db.transaction(async (tx) => {
    const results = await tx.all<SenderKeyRow>(`SELECT ${SENDER_KEY_COLUMNS} FROM sender_keys`);

    for (const row of results) {
      zeroStates(new SenderKey(row).states);
    }

    await tx.run('DELETE FROM sender_keys');
  });
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new sender key record.
 *
 * @param params - Sender key parameters
 * @param params.groupId - Group identifier
 * @param params.senderId - Sender identifier
 * @param params.deviceId - Device identifier
 * @param params.states - Sender key states, current state first
 * @returns New SenderKey instance (not yet persisted)
 */
export function createSenderKey(params: {
  groupId: string;
  senderId: string;
  deviceId: number;
  states: SenderKeyState[];
}): SenderKey {
  const now = Date.now();

  return new SenderKey({
    groupId: params.groupId,
    senderId: params.senderId,
    deviceId: params.deviceId,
    record: JSON.stringify(params.states),
    createdAt: now,
    updatedAt: now,
  });
}

// ============================================================================
// SenderKey Class
// ============================================================================

/**
 * SenderKey domain model with business logic methods.
 *
 * @example
 * ```typescript
 * // Store a sender key record
 * const senderKey = createSenderKey({
 *   groupId: 'group-123',
 *   senderId: 'user456',
 *   deviceId: 1,
 *   states: [currentState, previousState],
 * });
 * await senderKey.save(db);
 *
 * // Get a sender key record
 * const key = await getSenderKey(db, groupId, senderId, deviceId);
 * const current = key?.currentState;
 *
 * // List all sender key records for a group
 * const groupKeys = await getSenderKeysByGroup(db, groupId);
 *
 * // Delete sender key records for a group
 * await deleteSenderKeysByGroup(db, groupId);
 * ```
 */
export class SenderKey {
  private readonly data: SenderKeyRow;

  constructor(row: SenderKeyRow) {
    this.data = { ...row };
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Group identifier */
  get groupId(): string {
    return this.data.groupId;
  }

  /** Sender identifier */
  get senderId(): string {
    return this.data.senderId;
  }

  /** Device identifier */
  get deviceId(): number {
    return this.data.deviceId;
  }

  /** JSON-serialized `SenderKeyState[]`, current state first */
  get record(): string {
    return this.data.record;
  }

  /** Parsed states, current state first. Empty if the column is corrupt */
  get states(): SenderKeyState[] {
    return parseSenderKeyRecord(this.data.record);
  }

  /** Current state, or null if the record is empty or corrupt */
  get currentState(): SenderKeyState | null {
    return this.states[0] ?? null;
  }

  /** Superseded states still inside the rotation window */
  get previousStates(): SenderKeyState[] {
    return this.states.slice(1);
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  get updatedAt(): number {
    return this.data.updatedAt;
  }

  // ============================================================================
  // Serialization
  // ============================================================================

  /**
   * Convert to StoredSenderKey type.
   */
  toStoredSenderKey(): StoredSenderKey {
    return {
      groupId: this.groupId,
      senderId: this.senderId,
      deviceId: this.deviceId,
      record: this.record,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  // ============================================================================
  // Immutable Updates
  // ============================================================================

  /**
   * Create a new instance carrying a different set of states.
   * Called after ratcheting the chain forward or rotating the key.
   */
  withStates(states: SenderKeyState[]): SenderKey {
    return new SenderKey({
      ...this.data,
      record: JSON.stringify(states),
      updatedAt: Date.now(),
    });
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save the sender key record to the database.
   * Upserts on the primary key (groupId, senderId, deviceId).
   */
  async save(db: SqliteExecutor): Promise<void> {
    const now = Date.now();

    await db.run(
      `INSERT INTO sender_keys (group_id, sender_id, device_id, record, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (group_id, sender_id, device_id) DO UPDATE SET
         record = excluded.record,
         updated_at = excluded.updated_at`,
      [
        this.data.groupId,
        this.data.senderId,
        this.data.deviceId,
        this.data.record,
        this.data.createdAt,
        now,
      ]
    );
  }

  /**
   * Delete the sender key record from the database.
   * Securely zeros chain and signature keys before deletion (Section 8.1).
   */
  async delete(db: SqliteExecutor): Promise<void> {
    zeroStates(this.states);

    await db.run('DELETE FROM sender_keys WHERE group_id = ? AND sender_id = ? AND device_id = ?', [
      this.data.groupId,
      this.data.senderId,
      this.data.deviceId,
    ]);
  }
}
