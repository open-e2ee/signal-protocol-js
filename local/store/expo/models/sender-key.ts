/**
 * SenderKey Model
 *
 * Domain model for Signal Protocol Sender Keys using Drizzle ORM.
 * Sender Keys enable efficient O(1) group encryption.
 *
 * A row is the whole `SenderKeyState[]` record for one (group, sender, device)
 * triple, serialized into the `record` column: current state first, then the
 * superseded states the rotation window still needs. Primary key:
 * (groupId, senderId, deviceId).
 *
 * The chain keys and the sender's private signature key are in that column.
 * They stay on the device — the database file is SQLCipher-encrypted with an
 * application-supplied key, and this material is never sent to a server.
 */

import type { SenderKeyState } from '../../../../internal/protocol/sender-keys/manager';
import { getDrizzle, getRawDatabase, senderKeys, type NewSenderKey, eq, and, count } from '../db';

// Row type from Drizzle schema (internal)
export {};
type SenderKeyRow = typeof senderKeys.$inferSelect;
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
  groupId: string,
  senderId: string,
  deviceId: number
): Promise<SenderKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(senderKeys)
    .where(
      and(
        eq(senderKeys.groupId, groupId),
        eq(senderKeys.senderId, senderId),
        eq(senderKeys.deviceId, deviceId)
      )
    )
    .limit(1);

  return results.length > 0 ? new SenderKey(results[0]) : null;
}

/**
 * Get all sender key records for a group.
 *
 * @param groupId - Group identifier
 * @returns Array of SenderKey instances
 */
export async function getSenderKeysByGroup(groupId: string): Promise<SenderKey[]> {
  const db = await getDrizzle();
  const results = await db.select().from(senderKeys).where(eq(senderKeys.groupId, groupId));

  return results.map((row) => new SenderKey(row));
}

/**
 * Find the group whose sender key record contains an id, for one sender device.
 *
 * A received group message names its sender key by an opaque `senderKeyId` and
 * carries no group, so this is the receiver's only route back to a group.
 *
 * The lookup is a scan of that sender device's records rather than an index on
 * the id. Records here are stored as plaintext JSON — SQLCipher encrypts the
 * file, not the row — so a scan reads them directly, and it is bounded by the
 * groups shared with that one device. Indexing the ids would mean a second
 * table that can disagree with the records it points at; the correctness that
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
  senderKeyId: string,
  senderId: string,
  deviceId: number
): Promise<string | null> {
  if (!senderKeyId) return null;

  const db = await getDrizzle();
  const results = await db
    .select({ groupId: senderKeys.groupId, record: senderKeys.record })
    .from(senderKeys)
    .where(and(eq(senderKeys.senderId, senderId), eq(senderKeys.deviceId, deviceId)));

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
export async function getSenderKeysBySender(senderId: string): Promise<SenderKey[]> {
  const db = await getDrizzle();
  const results = await db.select().from(senderKeys).where(eq(senderKeys.senderId, senderId));

  return results.map((row) => new SenderKey(row));
}

/**
 * Count all sender key records.
 *
 * @returns Number of sender key records
 */
export async function countSenderKeys(): Promise<number> {
  const db = await getDrizzle();
  const results = await db.select({ count: count() }).from(senderKeys);
  return results[0]?.count ?? 0;
}

/**
 * Count sender key records for a group.
 *
 * @param groupId - Group identifier
 * @returns Number of sender key records for the group
 */
export async function countSenderKeysByGroup(groupId: string): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(senderKeys)
    .where(eq(senderKeys.groupId, groupId));
  return results[0]?.count ?? 0;
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
  groupId: string,
  senderId: string,
  deviceId: number
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    const senderKey = await getSenderKey(groupId, senderId, deviceId);
    if (senderKey) {
      zeroStates(senderKey.states);
    }

    const db = await getDrizzle();
    await db
      .delete(senderKeys)
      .where(
        and(
          eq(senderKeys.groupId, groupId),
          eq(senderKeys.senderId, senderId),
          eq(senderKeys.deviceId, deviceId)
        )
      );
  });
}

/**
 * Delete all sender key records for a group.
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
export async function deleteSenderKeysByGroup(groupId: string): Promise<number> {
  const rawDb = getRawDatabase();
  let deleted = 0;

  await rawDb.withTransactionAsync(async () => {
    const groupKeys = await getSenderKeysByGroup(groupId);
    for (const senderKey of groupKeys) {
      zeroStates(senderKey.states);
    }
    deleted = groupKeys.length;

    const db = await getDrizzle();
    await db.delete(senderKeys).where(eq(senderKeys.groupId, groupId));
  });

  return deleted;
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
export async function deleteSenderKeysBySender(senderId: string): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    const senderKeysList = await getSenderKeysBySender(senderId);
    for (const senderKey of senderKeysList) {
      zeroStates(senderKey.states);
    }

    const db = await getDrizzle();
    await db.delete(senderKeys).where(eq(senderKeys.senderId, senderId));
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
export async function deleteAllSenderKeys(): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    const db = await getDrizzle();
    const results = await db.select().from(senderKeys);

    for (const row of results) {
      zeroStates(new SenderKey(row).states);
    }

    await db.delete(senderKeys);
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
 * Uses Drizzle ORM directly for type-safe database operations.
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
 * await senderKey.save();
 *
 * // Get a sender key record
 * const key = await getSenderKey(groupId, senderId, deviceId);
 * const current = key?.currentState;
 *
 * // List all sender key records for a group
 * const groupKeys = await getSenderKeysByGroup(groupId);
 *
 * // Delete sender key records for a group
 * await deleteSenderKeysByGroup(groupId);
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

  /** Parsed states, current state first; empty if the column is corrupt */
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
  async save(): Promise<void> {
    const db = await getDrizzle();
    const now = Date.now();

    const insertData: NewSenderKey = {
      groupId: this.data.groupId,
      senderId: this.data.senderId,
      deviceId: this.data.deviceId,
      record: this.data.record,
      createdAt: this.data.createdAt,
      updatedAt: now,
    };

    await db
      .insert(senderKeys)
      .values(insertData)
      .onConflictDoUpdate({
        target: [senderKeys.groupId, senderKeys.senderId, senderKeys.deviceId],
        set: {
          record: insertData.record,
          updatedAt: now,
        },
      });
  }

  /**
   * Delete the sender key record from the database.
   * Securely zeros chain and signature keys before deletion (Section 8.1).
   */
  async delete(): Promise<void> {
    zeroStates(this.states);

    const db = await getDrizzle();
    await db
      .delete(senderKeys)
      .where(
        and(
          eq(senderKeys.groupId, this.data.groupId),
          eq(senderKeys.senderId, this.data.senderId),
          eq(senderKeys.deviceId, this.data.deviceId)
        )
      );
  }
}
