/**
 * Send log storage: resendable group content, its recipient rows, and the
 * persisted resend jobs.
 *
 * Each operation that touches more than one row runs in one transaction. The
 * store clock sets `createdAt`, so an application timestamp never changes
 * retention.
 */

import type {
  NewSendLogPayload,
  SendLogDevice,
  SendLogEntry,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
} from '../../../../types/api';
import {
  deleteAllSendLog,
  deleteFinishedSendLogPayload,
  deleteSendLogBefore,
  deleteSendLogPayload,
  deleteSendLogRecipient as modelDeleteSendLogRecipient,
  findSendLogEntries as modelFindSendLogEntries,
  findSendLogMessageIds,
  getPendingSendLogResendJobs,
  getSendLogEntry as modelGetSendLogEntry,
  getSendLogPayload,
  getSendLogRecipients as modelGetSendLogRecipients,
  getSendLogResendJob,
  incrementSendLogResendCount as modelIncrementSendLogResendCount,
  insertSendLogPayload,
  insertSendLogRecipients,
  saveSendLogResendJob,
  setSendLogComplete,
  setSendLogResendJobState,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

export async function storeSendLogEntry(
  ctx: KeyStorageContext,
  payload: NewSendLogPayload,
  recipients: readonly SendLogDevice[]
): Promise<void> {
  try {
    await ctx.db.transaction(async (tx) => {
      await deleteSendLogPayload(tx, payload.clientMessageId);
      await insertSendLogPayload(tx, payload, Date.now());
      await insertSendLogRecipients(tx, payload.clientMessageId, payload.clientTimestamp, recipients);
    });
  } catch (error) {
    throw keyStorageError('Failed to store send log entry', error);
  }
}

export async function appendSendLogRecipients(
  ctx: KeyStorageContext,
  clientMessageId: string,
  recipients: readonly SendLogDevice[]
): Promise<void> {
  try {
    await ctx.db.transaction(async (tx) => {
      const payload = await getSendLogPayload(tx, clientMessageId);
      if (payload === null) return;
      await insertSendLogRecipients(tx, clientMessageId, payload.clientTimestamp, recipients);
    });
  } catch (error) {
    throw keyStorageError('Failed to append send log recipients', error);
  }
}

export async function markSendLogComplete(
  ctx: KeyStorageContext,
  clientMessageId: string
): Promise<void> {
  try {
    await ctx.db.transaction(async (tx) => {
      if ((await setSendLogComplete(tx, clientMessageId)) === 0) return;
      await deleteFinishedSendLogPayload(tx, clientMessageId);
    });
  } catch (error) {
    throw keyStorageError('Failed to mark send log entry complete', error);
  }
}

export async function getSendLogEntry(
  ctx: KeyStorageContext,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<SendLogEntry | null> {
  try {
    return await modelGetSendLogEntry(ctx.db, clientMessageId, recipient);
  } catch (error) {
    throw keyStorageError('Failed to get send log entry', error);
  }
}

export async function findSendLogEntries(
  ctx: KeyStorageContext,
  recipient: SendLogDevice,
  clientTimestamp: number
): Promise<SendLogEntry[]> {
  try {
    return await modelFindSendLogEntries(ctx.db, recipient, clientTimestamp);
  } catch (error) {
    throw keyStorageError('Failed to find send log entries', error);
  }
}

export async function getSendLogRecipients(
  ctx: KeyStorageContext,
  clientMessageId: string
): Promise<SendLogRecipient[]> {
  try {
    return await modelGetSendLogRecipients(ctx.db, clientMessageId);
  } catch (error) {
    throw keyStorageError('Failed to get send log recipients', error);
  }
}

export async function deleteSendLogRecipient(
  ctx: KeyStorageContext,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<boolean> {
  try {
    return await ctx.db.transaction(async (tx) => {
      const deleted = await modelDeleteSendLogRecipient(tx, clientMessageId, recipient);
      if (deleted > 0) await deleteFinishedSendLogPayload(tx, clientMessageId);
      return deleted > 0;
    });
  } catch (error) {
    throw keyStorageError('Failed to delete send log recipient', error);
  }
}

export async function deleteSendLogRecipientsByTimestamp(
  ctx: KeyStorageContext,
  recipient: SendLogDevice,
  clientTimestamps: readonly number[]
): Promise<number> {
  try {
    return await ctx.db.transaction(async (tx) => {
      let deleted = 0;
      for (const clientTimestamp of new Set(clientTimestamps)) {
        for (const clientMessageId of await findSendLogMessageIds(tx, recipient, clientTimestamp)) {
          deleted += await modelDeleteSendLogRecipient(tx, clientMessageId, recipient);
          await deleteFinishedSendLogPayload(tx, clientMessageId);
        }
      }
      return deleted;
    });
  } catch (error) {
    throw keyStorageError('Failed to delete send log recipients by timestamp', error);
  }
}

export async function incrementSendLogResendCount(
  ctx: KeyStorageContext,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<number | null> {
  try {
    return await ctx.db.transaction((tx) =>
      modelIncrementSendLogResendCount(tx, clientMessageId, recipient)
    );
  } catch (error) {
    throw keyStorageError('Failed to count a send log resend', error);
  }
}

export async function deleteSendLogEntry(
  ctx: KeyStorageContext,
  clientMessageId: string
): Promise<boolean> {
  try {
    return (await ctx.db.transaction((tx) => deleteSendLogPayload(tx, clientMessageId))) > 0;
  } catch (error) {
    throw keyStorageError('Failed to delete send log entry', error);
  }
}

export async function deleteExpiredSendLog(
  ctx: KeyStorageContext,
  maxAgeMs: number
): Promise<number> {
  try {
    const cutoff = Date.now() - maxAgeMs;
    const deleted = await ctx.db.transaction((tx) => deleteSendLogBefore(tx, cutoff));
    if (deleted > 0) {
      ctx.logger.info('Deleted expired send log entries', {
        category: 'KeyStorage',
        data: { deleted, maxAgeMs },
      });
    }
    return deleted;
  } catch (error) {
    throw keyStorageError('Failed to delete expired send log entries', error);
  }
}

export async function clearSendLog(ctx: KeyStorageContext): Promise<number> {
  try {
    const deleted = await ctx.db.transaction(deleteAllSendLog);
    if (deleted > 0) {
      ctx.logger.info('Cleared the send log', { category: 'KeyStorage', data: { deleted } });
    }
    return deleted;
  } catch (error) {
    throw keyStorageError('Failed to clear the send log', error);
  }
}

export async function storeResendJob(
  ctx: KeyStorageContext,
  job: SendLogResendJob
): Promise<void> {
  try {
    await saveSendLogResendJob(ctx.db, job, Date.now());
  } catch (error) {
    throw keyStorageError('Failed to store resend job', error);
  }
}

export async function getResendJob(
  ctx: KeyStorageContext,
  jobId: string
): Promise<SendLogResendJob | null> {
  try {
    return await getSendLogResendJob(ctx.db, jobId);
  } catch (error) {
    throw keyStorageError('Failed to get resend job', error);
  }
}

export async function getPendingResendJobs(ctx: KeyStorageContext): Promise<SendLogResendJob[]> {
  try {
    return await getPendingSendLogResendJobs(ctx.db);
  } catch (error) {
    throw keyStorageError('Failed to get pending resend jobs', error);
  }
}

export async function completeResendJob(
  ctx: KeyStorageContext,
  jobId: string,
  state: Exclude<SendLogResendJobState, 'pending'>
): Promise<void> {
  try {
    await setSendLogResendJobState(ctx.db, jobId, state);
  } catch (error) {
    throw keyStorageError('Failed to complete resend job', error);
  }
}
