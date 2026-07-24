/**
 * MessageRecord Model
 *
 * Domain model for SESAME message records using Drizzle ORM.
 * Message records store plaintext for potential retry resending.
 *
 * Per SESAME Specification Section 4.1:
 * "The maxLatency setting serves as an upper bound on message age"
 *
 * Messages are indexed by the client timestamp assigned before encryption.
 * The primary key is sessionId + timestamp.
 *
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import {
  getDrizzle,
  getRawDatabase,
  messageRecords,
  type NewMessageRecord,
  eq,
  and,
  count,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type MessageRecordRow = typeof messageRecords.$inferSelect;

// ============================================================================
// Types
// ============================================================================

/**
 * Stored message record for SESAME retry requests.
 * Per SESAME Specification Section 4.1
 *
 * Messages are identified by the client timestamp assigned before encryption.
 */
export interface StoredMessageRecord {
  sessionId: string;
  /**
   * Client timestamp for message identification.
   * Set by sender BEFORE encryption. Used for retry request matching.
   */
  timestamp: number;
  recipientUserId: string;
  recipientDeviceId: number;
  plaintext: string;
  createdAt: number;
  /** Sender's ratchet key (DHs.publicKey) at send time — for retry session matching */
  sessionStateId: string;
}

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get message record by session and timestamp.
 * Called when handling a retry request to find the original plaintext.
 *
 * Per Signal Protocol, messages are identified by client timestamp.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @param timestamp - Client timestamp (set before encryption)
 * @returns MessageRecord instance or null if not found
 */
export async function getMessageRecord(
  sessionId: string,
  timestamp: number
): Promise<MessageRecord | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(messageRecords)
    .where(and(eq(messageRecords.sessionId, sessionId), eq(messageRecords.timestamp, timestamp)))
    .limit(1);

  return results.length > 0 ? new MessageRecord(results[0]) : null;
}

/**
 * Count message records.
 *
 * @returns Number of message records
 */
export async function countMessageRecords(): Promise<number> {
  const db = await getDrizzle();
  const results = await db.select({ count: count() }).from(messageRecords);
  return results[0]?.count ?? 0;
}

/**
 * Delete message record by session and timestamp.
 * Called after confirmed delivery.
 *
 * Per Signal Protocol, messages are identified by client timestamp.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @param timestamp - Client timestamp (set before encryption)
 */
export async function deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
  const db = await getDrizzle();
  await db
    .delete(messageRecords)
    .where(and(eq(messageRecords.sessionId, sessionId), eq(messageRecords.timestamp, timestamp)));
}

/**
 * Delete all expired message records older than maxAgeMs.
 *
 * Per SESAME spec: "The maxLatency setting serves as an upper bound on message age"
 *
 * Uses raw SQL to get actual deleted row count for conditional logging
 * in client.ts:3287-3293.
 *
 * @param maxAgeMs - Maximum age in milliseconds
 * @returns Number of deleted records
 */
export async function deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
  const rawDb = getRawDatabase();
  const cutoff = Date.now() - maxAgeMs;

  const result = await rawDb.runAsync(`DELETE FROM message_records WHERE created_at < ?`, [cutoff]);

  return result.changes ?? 0;
}

/**
 * Delete all message records.
 * Called when device re-registers and all local sessions are cleared.
 *
 * @returns Number of deleted records
 */
export async function deleteAllMessageRecords(): Promise<number> {
  const db = await getDrizzle();
  const deleted = await db.delete(messageRecords).returning();
  return deleted.length;
}

/**
 * Delete all message records for a session.
 * Called when a session is archived or deleted.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @returns Number of deleted records
 */
export async function deleteMessageRecordsBySessionId(sessionId: string): Promise<number> {
  const db = await getDrizzle();
  const deleted = await db
    .delete(messageRecords)
    .where(eq(messageRecords.sessionId, sessionId))
    .returning();
  return deleted.length;
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new message record.
 *
 * @param params - Message record parameters
 * @param params.sessionId - Session ID (format: userId:deviceId)
 * @param params.timestamp - Client timestamp set before encryption
 * @param params.recipientUserId - Recipient's user ID
 * @param params.recipientDeviceId - Recipient's device ID
 * @param params.plaintext - Original plaintext for retry
 * @param params.sessionStateId - Sender's ratchet key (DHs.publicKey) at send time
 * @param params.createdAt - Optional creation timestamp (defaults to Date.now())
 * @returns New MessageRecord instance (not yet persisted)
 */
export function createMessageRecord(params: {
  sessionId: string;
  /** Client timestamp - PRIMARY identifier for message lookup */
  timestamp: number;
  recipientUserId: string;
  recipientDeviceId: number;
  plaintext: string;
  sessionStateId: string;
  createdAt?: number;
}): MessageRecord {
  return new MessageRecord({
    sessionId: params.sessionId,
    timestamp: params.timestamp,
    recipientUserId: params.recipientUserId,
    recipientDeviceId: params.recipientDeviceId,
    plaintext: params.plaintext,
    createdAt: params.createdAt ?? Date.now(),
    sessionStateId: params.sessionStateId,
  });
}

// ============================================================================
// MessageRecord Class
// ============================================================================

/**
 * MessageRecord domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 * Per Signal Protocol, messages are identified by client timestamp.
 *
 * @example
 * ```typescript
 * // Store a message record after encryption
 * const record = createMessageRecord({
 *   sessionId: 'userId:deviceId',
 *   timestamp: Date.now(), // Client timestamp
 *   recipientUserId: 'userId',
 *   recipientDeviceId: 1,
 *   plaintext: 'Hello!',
 *   sessionStateId: 'senderDHsPublicKey',
 * });
 * await record.save();
 *
 * // Get record for retry
 * const stored = await getMessageRecord(sessionId, timestamp);
 *
 * // Delete after confirmed delivery
 * await deleteMessageRecord(sessionId, timestamp);
 *
 * // Clean up expired records
 * await deleteExpiredMessageRecords(maxAgeMs);
 * ```
 */
export class MessageRecord {
  private readonly data: MessageRecordRow;

  constructor(row: MessageRecordRow) {
    this.data = { ...row };
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Session ID (format: userId:deviceId) */
  get sessionId(): string {
    return this.data.sessionId;
  }

  /** Client timestamp for message identification */
  get timestamp(): number {
    return this.data.timestamp;
  }

  /** Recipient's user ID */
  get recipientUserId(): string {
    return this.data.recipientUserId;
  }

  /** Recipient's device ID */
  get recipientDeviceId(): number {
    return this.data.recipientDeviceId;
  }

  /** Original plaintext for retry */
  get plaintext(): string {
    return this.data.plaintext;
  }

  /** Creation timestamp */
  get createdAt(): number {
    return this.data.createdAt;
  }

  /** Sender's ratchet key (DHs.publicKey) at send time — for retry session matching */
  get sessionStateId(): string {
    return this.data.sessionStateId;
  }

  // ============================================================================
  // Serialization
  // ============================================================================

  /**
   * Convert to StoredMessageRecord type.
   */
  toStoredMessageRecord(): StoredMessageRecord {
    return {
      sessionId: this.sessionId,
      timestamp: this.timestamp,
      recipientUserId: this.recipientUserId,
      recipientDeviceId: this.recipientDeviceId,
      plaintext: this.plaintext,
      createdAt: this.createdAt,
      sessionStateId: this.sessionStateId,
    };
  }

  // ============================================================================
  // Immutable Updates
  // ============================================================================

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save message record to database.
   */
  async save(): Promise<void> {
    const db = await getDrizzle();

    const insertData: NewMessageRecord = {
      sessionId: this.data.sessionId,
      timestamp: this.data.timestamp,
      recipientUserId: this.data.recipientUserId,
      recipientDeviceId: this.data.recipientDeviceId,
      plaintext: this.data.plaintext,
      createdAt: this.data.createdAt,
      sessionStateId: this.data.sessionStateId,
    };

    // Use composite primary key conflict handling
    await db
      .insert(messageRecords)
      .values(insertData)
      .onConflictDoUpdate({
        target: [messageRecords.sessionId, messageRecords.timestamp],
        set: {
          recipientUserId: insertData.recipientUserId,
          recipientDeviceId: insertData.recipientDeviceId,
          plaintext: insertData.plaintext,
          sessionStateId: insertData.sessionStateId,
        },
      });
  }

  /**
   * Delete message record from database.
   */
  async delete(): Promise<void> {
    const db = await getDrizzle();
    await db
      .delete(messageRecords)
      .where(
        and(
          eq(messageRecords.sessionId, this.data.sessionId),
          eq(messageRecords.timestamp, this.data.timestamp)
        )
      );
  }

  // ============================================================================
  // Static Methods
  // ============================================================================

  /** Create MessageRecord from database row */
  static fromStored(stored: MessageRecordRow): MessageRecord {
    return new MessageRecord(stored);
  }

  /** Create a new MessageRecord instance */
  static create(params: {
    sessionId: string;
    timestamp: number;
    recipientUserId: string;
    recipientDeviceId: number;
    plaintext: string;
    sessionStateId: string;
  }): MessageRecord {
    return createMessageRecord(params);
  }

  /** Get message record by session and timestamp */
  static async get(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    return getMessageRecord(sessionId, timestamp);
  }

  /** Delete message record by session and timestamp */
  static async delete(sessionId: string, timestamp: number): Promise<void> {
    return deleteMessageRecord(sessionId, timestamp);
  }

  /** Delete expired message records */
  static async deleteExpired(maxAgeMs: number): Promise<number> {
    return deleteExpiredMessageRecords(maxAgeMs);
  }

  /** Delete all message records */
  static async deleteAll(): Promise<number> {
    return deleteAllMessageRecords();
  }

  /** Count all message records */
  static async count(): Promise<number> {
    return countMessageRecords();
  }

  /** Delete this message record from database */
  async remove(): Promise<void> {
    return this.delete();
  }
}
