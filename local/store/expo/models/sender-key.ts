/**
 * SenderKey Model
 *
 * Domain model for Signal Protocol Sender Keys using Drizzle ORM.
 * Sender Keys enable efficient O(1) group encryption.
 *
 * ID: autoincrement integer. Unique constraint: (distributionId, senderId, deviceId).
 *
 *
 * @see https://signal.org/blog/sesame-protocol-review/
 */

import { getDrizzle, getRawDatabase, senderKeys, type NewSenderKey, eq, and, count } from '../db';

// Row type from Drizzle schema (internal)
export {};
type SenderKeyRow = typeof senderKeys.$inferSelect;
import { secureZero } from '../../../../internal/crypto';

// ============================================================================
// Types
// ============================================================================

/**
 * Sender Key for group messaging.
 *
 * Note: Uses plain strings (not branded Base64) because this data is
 * serialized/deserialized from SQLite.
 */
export interface StoredSenderKey {
  id: number; // autoincrement row ID
  distributionId: string;
  senderId: string;
  deviceId: number;
  chainKey: string;
  iteration: number;
  previousStates: string | null; // JSON-serialized SenderKeyState[] for rotation window
  createdAt: number;
  updatedAt: number;
}

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get sender key by distribution, sender, and device.
 *
 * @param distributionId - Distribution identifier (UUID, distinct from group ID per reference convention)
 * @param senderId - Sender identifier
 * @param deviceId - Device identifier
 * @returns SenderKey instance or null if not found
 */
export async function getSenderKey(
  distributionId: string,
  senderId: string,
  deviceId: number
): Promise<SenderKey | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(senderKeys)
    .where(
      and(
        eq(senderKeys.distributionId, distributionId),
        eq(senderKeys.senderId, senderId),
        eq(senderKeys.deviceId, deviceId)
      )
    )
    .limit(1);

  return results.length > 0 ? new SenderKey(results[0]) : null;
}

/**
 * Get sender key by integer row ID.
 *
 * @param id - Autoincrement row ID
 * @returns SenderKey instance or null if not found
 */
export async function getSenderKeyById(id: number): Promise<SenderKey | null> {
  const db = await getDrizzle();
  const results = await db.select().from(senderKeys).where(eq(senderKeys.id, id)).limit(1);

  return results.length > 0 ? new SenderKey(results[0]) : null;
}

/**
 * Get all sender keys for a distribution.
 *
 * @param distributionId - Distribution identifier
 * @returns Array of SenderKey instances
 */
export async function getSenderKeysByDistribution(distributionId: string): Promise<SenderKey[]> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(senderKeys)
    .where(eq(senderKeys.distributionId, distributionId));

  return results.map((row) => new SenderKey(row));
}

/**
 * Get all sender keys for a sender.
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
 * Count all sender keys.
 *
 * @returns Number of sender keys
 */
export async function countSenderKeys(): Promise<number> {
  const db = await getDrizzle();
  const results = await db.select({ count: count() }).from(senderKeys);
  return results[0]?.count ?? 0;
}

/**
 * Count sender keys by distribution.
 *
 * @param distributionId - Distribution identifier
 * @returns Number of sender keys for the distribution
 */
export async function countSenderKeysByDistribution(distributionId: string): Promise<number> {
  const db = await getDrizzle();
  const results = await db
    .select({ count: count() })
    .from(senderKeys)
    .where(eq(senderKeys.distributionId, distributionId));
  return results[0]?.count ?? 0;
}

/**
 * Delete sender key by distribution, sender, and device.
 * Securely zeros chain key before deletion (Section 8.1).
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param distributionId - Distribution identifier
 * @param senderId - Sender identifier
 * @param deviceId - Device identifier
 */
export async function deleteSenderKey(
  distributionId: string,
  senderId: string,
  deviceId: number
): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch sender key to securely zero chain key
    const senderKey = await getSenderKey(distributionId, senderId, deviceId);
    if (senderKey) {
      secureZero(senderKey.chainKey);
    }

    const db = await getDrizzle();
    await db
      .delete(senderKeys)
      .where(
        and(
          eq(senderKeys.distributionId, distributionId),
          eq(senderKeys.senderId, senderId),
          eq(senderKeys.deviceId, deviceId)
        )
      );
  });
}

/**
 * Delete all sender keys for a distribution.
 * Securely zeros all chain keys before deletion (Section 8.1).
 * Called when leaving a group or when group is deleted.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param distributionId - Distribution identifier
 */
export async function deleteSenderKeysByDistribution(distributionId: string): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch all sender keys for distribution to securely zero chain keys
    const distKeys = await getSenderKeysByDistribution(distributionId);
    for (const senderKey of distKeys) {
      secureZero(senderKey.chainKey);
    }

    const db = await getDrizzle();
    await db.delete(senderKeys).where(eq(senderKeys.distributionId, distributionId));
  });
}

/**
 * Delete all sender keys for a sender.
 * Securely zeros all chain keys before deletion (Section 8.1).
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
    // Fetch all sender keys for sender to securely zero chain keys
    const senderKeysList = await getSenderKeysBySender(senderId);
    for (const senderKey of senderKeysList) {
      secureZero(senderKey.chainKey);
    }

    const db = await getDrizzle();
    await db.delete(senderKeys).where(eq(senderKeys.senderId, senderId));
  });
}

/**
 * Delete all sender keys.
 * Securely zeros all chain keys before deletion (Section 8.1).
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 */
export async function deleteAllSenderKeys(): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Fetch all sender keys to securely zero chain keys
    const db = await getDrizzle();
    const results = await db.select().from(senderKeys);

    for (const row of results) {
      const senderKey = new SenderKey(row);
      secureZero(senderKey.chainKey);
    }

    await db.delete(senderKeys);
  });
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new sender key.
 *
 * @param params - Sender key parameters
 * @param params.distributionId - Distribution identifier (UUID, distinct from group ID per reference convention)
 * @param params.senderId - Sender identifier
 * @param params.deviceId - Device identifier
 * @param params.chainKey - Chain key (base64 or Uint8Array)
 * @param params.iteration - Current chain iteration
 * @returns New SenderKey instance (not yet persisted)
 */
export function createSenderKey(params: {
  distributionId: string;
  senderId: string;
  deviceId: number;
  chainKey: string | Uint8Array;
  iteration: number;
}): SenderKey {
  const now = Date.now();

  const chainKey =
    typeof params.chainKey === 'string'
      ? params.chainKey
      : Buffer.from(params.chainKey).toString('base64');

  return new SenderKey({
    id: 0, // Placeholder; autoincrement assigns real ID on insert
    distributionId: params.distributionId,
    senderId: params.senderId,
    deviceId: params.deviceId,
    chainKey,
    iteration: params.iteration,
    previousStates: null,
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
 * // Store a sender key
 * const senderKey = createSenderKey({
 *   distributionId: 'dist-uuid-123',
 *   senderId: 'user456',
 *   deviceId: 1,
 *   chainKey: 'base64...',
 *   iteration: 0,
 * });
 * await senderKey.save();
 *
 * // Get sender key
 * const key = await getSenderKey(distributionId, senderId, deviceId);
 *
 * // List all sender keys for a distribution
 * const distKeys = await getSenderKeysByDistribution(distributionId);
 *
 * // Delete sender keys for a distribution
 * await deleteSenderKeysByDistribution(distributionId);
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

  /** Autoincrement row ID */
  get id(): number {
    return this.data.id;
  }

  /** Distribution identifier (UUID, distinct from group ID per reference convention) */
  get distributionId(): string {
    return this.data.distributionId;
  }

  /** Sender identifier */
  get senderId(): string {
    return this.data.senderId;
  }

  /** Device identifier */
  get deviceId(): number {
    return this.data.deviceId;
  }

  /** Chain key (base64 encoded) */
  get chainKey(): string {
    return this.data.chainKey;
  }

  /** Chain key as Uint8Array */
  get chainKeyBytes(): Uint8Array {
    return Uint8Array.from(Buffer.from(this.data.chainKey, 'base64'));
  }

  /** Current chain iteration */
  get iteration(): number {
    return this.data.iteration;
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  get updatedAt(): number {
    return this.data.updatedAt;
  }

  /** JSON-serialized previous states, or null if none */
  get previousStates(): string | null {
    return this.data.previousStates;
  }

  // ============================================================================
  // Serialization
  // ============================================================================

  /**
   * Convert to StoredSenderKey type.
   */
  toStoredSenderKey(): StoredSenderKey {
    return {
      id: this.id,
      distributionId: this.distributionId,
      senderId: this.senderId,
      deviceId: this.deviceId,
      chainKey: this.chainKey,
      iteration: this.iteration,
      previousStates: this.previousStates,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  // ============================================================================
  // Immutable Updates
  // ============================================================================

  /**
   * Create a new instance with updated chain key and iteration.
   * Called after ratcheting the chain forward.
   */
  withRatcheted(newChainKey: string | Uint8Array, newIteration: number): SenderKey {
    const now = Date.now();
    const chainKey =
      typeof newChainKey === 'string' ? newChainKey : Buffer.from(newChainKey).toString('base64');

    return new SenderKey({
      ...this.data,
      chainKey,
      iteration: newIteration,
      updatedAt: now,
    });
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save sender key to database.
   * Upserts on the unique constraint (distributionId, senderId, deviceId).
   */
  async save(): Promise<void> {
    const db = await getDrizzle();
    const now = Date.now();

    const insertData: NewSenderKey = {
      distributionId: this.data.distributionId,
      senderId: this.data.senderId,
      deviceId: this.data.deviceId,
      chainKey: this.data.chainKey,
      iteration: this.data.iteration,
      previousStates: this.data.previousStates,
      createdAt: this.data.createdAt,
      updatedAt: now,
    };

    await db
      .insert(senderKeys)
      .values(insertData)
      .onConflictDoUpdate({
        target: [senderKeys.distributionId, senderKeys.senderId, senderKeys.deviceId],
        set: {
          chainKey: insertData.chainKey,
          iteration: insertData.iteration,
          previousStates: insertData.previousStates,
          updatedAt: now,
        },
      });
  }

  /**
   * Delete sender key from database.
   * Securely zeros chain key before deletion (Section 8.1).
   */
  async delete(): Promise<void> {
    // Securely zero chain key before deletion
    secureZero(this.data.chainKey);

    const db = await getDrizzle();
    await db
      .delete(senderKeys)
      .where(
        and(
          eq(senderKeys.distributionId, this.data.distributionId),
          eq(senderKeys.senderId, this.data.senderId),
          eq(senderKeys.deviceId, this.data.deviceId)
        )
      );
  }
}
