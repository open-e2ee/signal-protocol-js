/**
 * MessageRecord storage (SESAME retry request support), per SESAME
 * Specification Section 6.2.
 *
 * Retry records are indexed by the client timestamp assigned before
 * encryption. The primary lookup is getMessageRecord().
 */

import type { MessageRecord } from '../../../../types';
import {
  countMessageRecords,
  createMessageRecord,
  deleteAllMessageRecords,
  deleteExpiredMessageRecords as modelDeleteExpiredMessageRecords,
  deleteMessageRecord as modelDeleteMessageRecord,
  deleteMessageRecordsBySessionId,
  getMessageRecord as modelGetMessageRecord,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

/**
 * Store a message record for potential retry resending
 *
 * Called after successful encryption to store the plaintext.
 * Record is deleted after confirmed delivery or expiration.
 */
export async function storeMessageRecord(
  ctx: KeyStorageContext,
  record: MessageRecord
): Promise<void> {
  try {
    const messageRecordModel = createMessageRecord({
      sessionId: record.sessionId,
      timestamp: record.timestamp,
      recipientUserId: record.recipientUserId,
      recipientDeviceId: record.recipientDeviceId,
      plaintext: record.plaintext,
      sessionStateId: record.sessionStateId,
      createdAt: record.createdAt,
    });
    await messageRecordModel.save(ctx.db);

    ctx.logger.debug('Stored message record for retry support', {
      category: 'KeyStorage',
      data: {
        sessionId: record.sessionId,
        timestamp: record.timestamp,
        recipient: `${record.recipientUserId}:${record.recipientDeviceId}`,
      },
    });
  } catch (error) {
    throw keyStorageError(
      `Failed to store message record ${record.sessionId}:${record.timestamp}`,
      error
    );
  }
}

export async function getMessageRecord(
  ctx: KeyStorageContext,
  sessionId: string,
  timestamp: number
): Promise<MessageRecord | null> {
  try {
    const record = await modelGetMessageRecord(ctx.db, sessionId, timestamp);
    return record?.toStoredMessageRecord() ?? null;
  } catch (error) {
    throw keyStorageError(`Failed to get message record ${sessionId}:${timestamp}`, error);
  }
}

/**
 * Delete all expired message records older than maxAgeMs
 *
 * Per SESAME spec: "The maxLatency setting serves as an upper bound on message age"
 */
export async function deleteExpiredMessageRecords(
  ctx: KeyStorageContext,
  maxAgeMs: number
): Promise<number> {
  try {
    const deleted = await modelDeleteExpiredMessageRecords(ctx.db, maxAgeMs);

    if (deleted > 0) {
      ctx.logger.info('Deleted expired message records', {
        category: 'KeyStorage',
        data: { deleted, maxAgeMs },
      });
    }

    return deleted;
  } catch (error) {
    throw keyStorageError('Failed to delete expired message records', error);
  }
}

/**
 * Clear all message records
 *
 * Called when device re-registers and all local sessions are cleared.
 * All stored message records become orphaned and should be deleted.
 */
export async function clearAllMessageRecords(ctx: KeyStorageContext): Promise<number> {
  try {
    const deleted = await deleteAllMessageRecords(ctx.db);

    if (deleted > 0) {
      ctx.logger.info('Cleared all message records', {
        category: 'KeyStorage',
        data: { deleted },
      });
    }

    return deleted;
  } catch (error) {
    throw keyStorageError('Failed to clear message records', error);
  }
}

/** Delete all message records for a session, when it is archived or deleted. */
export async function deleteMessageRecordsForSession(
  ctx: KeyStorageContext,
  sessionId: string
): Promise<number> {
  try {
    const deleted = await deleteMessageRecordsBySessionId(ctx.db, sessionId);

    if (deleted > 0) {
      ctx.logger.debug('Deleted message records for session', {
        category: 'KeyStorage',
        data: { sessionId, deleted },
      });
    }

    return deleted;
  } catch (error) {
    throw keyStorageError(`Failed to delete message records for session ${sessionId}`, error);
  }
}

export async function getMessageRecordCount(ctx: KeyStorageContext): Promise<number> {
  try {
    return await countMessageRecords(ctx.db);
  } catch (error) {
    throw keyStorageError('Failed to get message record count', error);
  }
}

/**
 * Delete a message record by session and timestamp.
 *
 * Called when processing delivery receipts to clean up confirmed messages.
 * Per Signal Protocol, messages are identified by client timestamp.
 */
export async function deleteMessageRecord(
  ctx: KeyStorageContext,
  sessionId: string,
  timestamp: number
): Promise<void> {
  try {
    await modelDeleteMessageRecord(ctx.db, sessionId, timestamp);

    ctx.logger.debug('Deleted message record after delivery receipt', {
      category: 'KeyStorage',
      data: { sessionId, timestamp },
    });
  } catch (error) {
    throw keyStorageError(`Failed to delete message record ${sessionId}:${timestamp}`, error);
  }
}
