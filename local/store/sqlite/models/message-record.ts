/**
 * MessageRecord Model
 *
 * Domain model for SESAME message records.
 * Message records store plaintext for potential retry resending.
 *
 * Per SESAME Specification Section 4.1:
 * "The maxLatency setting serves as an upper bound on message age"
 *
 * Messages are indexed by the client timestamp assigned before encryption.
 * The primary key is sessionId + timestamp.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import type { SqliteExecutor } from '../driver';
import { MESSAGE_RECORD_COLUMNS, type MessageRecordRow } from '../schema';

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
  /** Sender's ratchet key (DHs.publicKey) at send time, for retry session matching */
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
  db: SqliteExecutor,
  sessionId: string,
  timestamp: number
): Promise<MessageRecord | null> {
  const row = await db.first<MessageRecordRow>(
    `SELECT ${MESSAGE_RECORD_COLUMNS} FROM message_records
     WHERE session_id = ? AND timestamp = ? LIMIT 1`,
    [sessionId, timestamp]
  );

  return row ? new MessageRecord(row) : null;
}

/**
 * Count message records.
 *
 * @returns Number of message records
 */
export async function countMessageRecords(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ count: number }>('SELECT COUNT(*) AS count FROM message_records');
  return row?.count ?? 0;
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
export async function deleteMessageRecord(
  db: SqliteExecutor,
  sessionId: string,
  timestamp: number
): Promise<void> {
  await db.run('DELETE FROM message_records WHERE session_id = ? AND timestamp = ?', [
    sessionId,
    timestamp,
  ]);
}

/**
 * Delete all expired message records older than maxAgeMs.
 *
 * Per SESAME spec: "The maxLatency setting serves as an upper bound on message age"
 *
 * @param maxAgeMs - Maximum age in milliseconds
 * @returns Number of deleted records
 */
export async function deleteExpiredMessageRecords(
  db: SqliteExecutor,
  maxAgeMs: number
): Promise<number> {
  const cutoff = Date.now() - maxAgeMs;
  return db.run('DELETE FROM message_records WHERE created_at < ?', [cutoff]);
}

/**
 * Delete all message records.
 * Called when device re-registers and all local sessions are cleared.
 *
 * @returns Number of deleted records
 */
export async function deleteAllMessageRecords(db: SqliteExecutor): Promise<number> {
  return db.run('DELETE FROM message_records');
}

/**
 * Delete all message records for a session.
 * Called when a session is archived or deleted.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @returns Number of deleted records
 */
export async function deleteMessageRecordsBySessionId(
  db: SqliteExecutor,
  sessionId: string
): Promise<number> {
  return db.run('DELETE FROM message_records WHERE session_id = ?', [sessionId]);
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
 * await record.save(db);
 *
 * // Get record for retry
 * const stored = await getMessageRecord(db, sessionId, timestamp);
 *
 * // Delete after confirmed delivery
 * await deleteMessageRecord(db, sessionId, timestamp);
 *
 * // Clean up expired records
 * await deleteExpiredMessageRecords(db, maxAgeMs);
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

  /** Sender's ratchet key (DHs.publicKey) at send time, for retry session matching */
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
  // Persistence
  // ============================================================================

  /**
   * Save message record to database.
   */
  async save(db: SqliteExecutor): Promise<void> {
    // Use composite primary key conflict handling
    await db.run(
      `INSERT INTO message_records (session_id, timestamp, recipient_user_id,
         recipient_device_id, plaintext, created_at, session_state_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (session_id, timestamp) DO UPDATE SET
         recipient_user_id = excluded.recipient_user_id,
         recipient_device_id = excluded.recipient_device_id,
         plaintext = excluded.plaintext,
         session_state_id = excluded.session_state_id`,
      [
        this.data.sessionId,
        this.data.timestamp,
        this.data.recipientUserId,
        this.data.recipientDeviceId,
        this.data.plaintext,
        this.data.createdAt,
        this.data.sessionStateId,
      ]
    );
  }

  /**
   * Delete message record from database.
   */
  async delete(db: SqliteExecutor): Promise<void> {
    await deleteMessageRecord(db, this.data.sessionId, this.data.timestamp);
  }
}
