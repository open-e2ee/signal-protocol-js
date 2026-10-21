/**
 * The send log: resendable group content and the recipient devices that have
 * not confirmed it, plus the persisted resend jobs.
 *
 * A payload row holds the plaintext. A recipient row authorizes a resend to
 * one device. A payload with no recipient row is deleted once its send
 * finished. Each statement uses the executor that the caller passes, so the
 * key storage composes them in one transaction.
 */

import type { SqliteExecutor } from '../driver';
import {
  SEND_LOG_PAYLOAD_COLUMNS,
  SEND_LOG_RECIPIENT_COLUMNS,
  SEND_LOG_RESEND_JOB_COLUMNS,
  type SendLogPayloadRow,
  type SendLogRecipientRow,
  type SendLogResendJobRow,
} from '../schema';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import { asBase64 } from '../../../../types/utils';
import type {
  NewSendLogPayload,
  SendLogDevice,
  SendLogEntry,
  SendLogPayload,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
} from '../../../../types/api';
import type { ContentHint } from '../../../../types/messages';

const RESEND_JOB_STATES: readonly SendLogResendJobState[] = ['pending', 'posted', 'abandoned'];

/** The columns of a joined payload and recipient row, with distinct aliases. */
const ENTRY_COLUMNS = `p.client_message_id AS clientMessageId, p.group_id AS groupId,
  p.client_timestamp AS clientTimestamp, p.content_hint AS contentHint, p.plaintext,
  p.created_at AS createdAt, p.send_complete AS sendComplete,
  r.user_id AS userId, r.device_id AS deviceId, r.responses`;

type EntryRow = SendLogPayloadRow & Pick<SendLogRecipientRow, 'userId' | 'deviceId' | 'responses'>;

function payloadFromRow(row: SendLogPayloadRow): SendLogPayload {
  return {
    clientMessageId: row.clientMessageId,
    groupId: row.groupId,
    clientTimestamp: row.clientTimestamp,
    contentHint: row.contentHint as ContentHint,
    plaintext: base64ToBytes(asBase64(row.plaintext)),
    createdAt: row.createdAt,
    sendComplete: row.sendComplete === 1,
  };
}

function recipientFromRow(row: SendLogRecipientRow): SendLogRecipient {
  return {
    clientMessageId: row.clientMessageId,
    userId: row.userId,
    deviceId: row.deviceId,
    clientTimestamp: row.clientTimestamp,
    responses: row.responses,
  };
}

function entryFromRow(row: EntryRow): SendLogEntry {
  return {
    payload: payloadFromRow(row),
    recipient: recipientFromRow(row),
  };
}

function resendJobFromRow(row: SendLogResendJobRow): SendLogResendJob {
  const state = RESEND_JOB_STATES.find((value) => value === row.state);
  if (state === undefined) throw new Error(`Unknown resend job state ${row.state}`);
  return {
    jobId: row.jobId,
    clientMessageId: row.clientMessageId,
    requesterUserId: row.requesterUserId,
    requesterDeviceId: row.requesterDeviceId,
    retryId: row.retryId,
    requestEnvelopeId: row.requestEnvelopeId,
    ...(row.failedEnvelopeId !== null && { failedEnvelopeId: row.failedEnvelopeId }),
    createdAt: row.createdAt,
    attempts: row.attempts,
    state,
  };
}

/** Write a payload row that the send has not finished. */
export async function insertSendLogPayload(
  db: SqliteExecutor,
  payload: NewSendLogPayload,
  createdAt: number
): Promise<void> {
  await db.run(
    `INSERT INTO send_log_payload (client_message_id, group_id, client_timestamp,
       content_hint, plaintext, created_at, send_complete)
     VALUES (?, ?, ?, ?, ?, ?, 0)`,
    [
      payload.clientMessageId,
      payload.groupId,
      payload.clientTimestamp,
      payload.contentHint,
      bytesToBase64(payload.plaintext),
      createdAt,
    ]
  );
}

export async function getSendLogPayload(
  db: SqliteExecutor,
  clientMessageId: string
): Promise<SendLogPayload | null> {
  const row = await db.first<SendLogPayloadRow>(
    `SELECT ${SEND_LOG_PAYLOAD_COLUMNS} FROM send_log_payload WHERE client_message_id = ? LIMIT 1`,
    [clientMessageId]
  );
  return row ? payloadFromRow(row) : null;
}

/**
 * Add a row for each device at the client timestamp of the payload. An
 * existing row is kept unchanged.
 */
export async function insertSendLogRecipients(
  db: SqliteExecutor,
  clientMessageId: string,
  clientTimestamp: number,
  recipients: readonly SendLogDevice[]
): Promise<void> {
  for (const recipient of recipients) {
    await db.run(
      `INSERT INTO send_log_recipient (client_message_id, user_id, device_id, client_timestamp, responses)
       VALUES (?, ?, ?, ?, 0)
       ON CONFLICT (client_message_id, user_id, device_id) DO NOTHING`,
      [clientMessageId, recipient.userId, recipient.deviceId, clientTimestamp]
    );
  }
}

export async function setSendLogComplete(
  db: SqliteExecutor,
  clientMessageId: string
): Promise<number> {
  return db.run('UPDATE send_log_payload SET send_complete = 1 WHERE client_message_id = ?', [
    clientMessageId,
  ]);
}

/** Delete the payload when its send finished and no recipient row remains. */
export async function deleteFinishedSendLogPayload(
  db: SqliteExecutor,
  clientMessageId: string
): Promise<number> {
  return db.run(
    `DELETE FROM send_log_payload
     WHERE client_message_id = ? AND send_complete = 1
       AND NOT EXISTS (SELECT 1 FROM send_log_recipient WHERE client_message_id = ?)`,
    [clientMessageId, clientMessageId]
  );
}

/**
 * Delete a payload and its recipient rows. The rows are deleted first, so the
 * result does not depend on the foreign key setting of the connection.
 */
export async function deleteSendLogPayload(
  db: SqliteExecutor,
  clientMessageId: string
): Promise<number> {
  await db.run('DELETE FROM send_log_recipient WHERE client_message_id = ?', [clientMessageId]);
  return db.run('DELETE FROM send_log_payload WHERE client_message_id = ?', [clientMessageId]);
}

export async function getSendLogEntry(
  db: SqliteExecutor,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<SendLogEntry | null> {
  const row = await db.first<EntryRow>(
    `SELECT ${ENTRY_COLUMNS} FROM send_log_recipient r
     JOIN send_log_payload p ON p.client_message_id = r.client_message_id
     WHERE r.client_message_id = ? AND r.user_id = ? AND r.device_id = ? LIMIT 1`,
    [clientMessageId, recipient.userId, recipient.deviceId]
  );
  return row ? entryFromRow(row) : null;
}

export async function findSendLogEntries(
  db: SqliteExecutor,
  recipient: SendLogDevice,
  clientTimestamp: number
): Promise<SendLogEntry[]> {
  const rows = await db.all<EntryRow>(
    `SELECT ${ENTRY_COLUMNS} FROM send_log_recipient r
     JOIN send_log_payload p ON p.client_message_id = r.client_message_id
     WHERE r.user_id = ? AND r.device_id = ? AND r.client_timestamp = ?
     ORDER BY r.client_message_id`,
    [recipient.userId, recipient.deviceId, clientTimestamp]
  );
  return rows.map(entryFromRow);
}

export async function getSendLogRecipients(
  db: SqliteExecutor,
  clientMessageId: string
): Promise<SendLogRecipient[]> {
  const rows = await db.all<SendLogRecipientRow>(
    `SELECT ${SEND_LOG_RECIPIENT_COLUMNS} FROM send_log_recipient
     WHERE client_message_id = ? ORDER BY user_id, device_id`,
    [clientMessageId]
  );
  return rows.map(recipientFromRow);
}

/** The IDs of the sends that have a row for the device at the client timestamp. */
export async function findSendLogMessageIds(
  db: SqliteExecutor,
  recipient: SendLogDevice,
  clientTimestamp: number
): Promise<string[]> {
  const rows = await db.all<{ clientMessageId: string }>(
    `SELECT client_message_id AS clientMessageId FROM send_log_recipient
     WHERE user_id = ? AND device_id = ? AND client_timestamp = ?`,
    [recipient.userId, recipient.deviceId, clientTimestamp]
  );
  return rows.map((row) => row.clientMessageId);
}

export async function deleteSendLogRecipient(
  db: SqliteExecutor,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<number> {
  return db.run(
    'DELETE FROM send_log_recipient WHERE client_message_id = ? AND user_id = ? AND device_id = ?',
    [clientMessageId, recipient.userId, recipient.deviceId]
  );
}

/** Add one to the resend count of a row. Returns the new count, or null with no row. */
export async function incrementSendLogResendCount(
  db: SqliteExecutor,
  clientMessageId: string,
  recipient: SendLogDevice
): Promise<number | null> {
  const where = 'client_message_id = ? AND user_id = ? AND device_id = ?';
  const params = [clientMessageId, recipient.userId, recipient.deviceId];
  const changed = await db.run(
    `UPDATE send_log_recipient SET responses = responses + 1 WHERE ${where}`,
    params
  );
  if (changed === 0) return null;
  const row = await db.first<{ responses: number }>(
    `SELECT responses FROM send_log_recipient WHERE ${where} LIMIT 1`,
    params
  );
  return row?.responses ?? null;
}

/**
 * Delete each payload, with its rows, and each resend job that the store
 * wrote before `cutoff`. Returns the number of deleted payloads.
 */
export async function deleteSendLogBefore(db: SqliteExecutor, cutoff: number): Promise<number> {
  await db.run(
    `DELETE FROM send_log_recipient WHERE client_message_id IN
       (SELECT client_message_id FROM send_log_payload WHERE created_at < ?)`,
    [cutoff]
  );
  const deleted = await db.run('DELETE FROM send_log_payload WHERE created_at < ?', [cutoff]);
  await db.run('DELETE FROM send_log_resend_job WHERE created_at < ?', [cutoff]);
  return deleted;
}

/** Delete every payload, row, and resend job. Returns the number of deleted payloads. */
export async function deleteAllSendLog(db: SqliteExecutor): Promise<number> {
  await db.run('DELETE FROM send_log_recipient');
  const deleted = await db.run('DELETE FROM send_log_payload');
  await db.run('DELETE FROM send_log_resend_job');
  return deleted;
}

/**
 * Write a resend job. A new job gets `createdAt`. A job with the same ID is
 * replaced, except its first `createdAt`, which stays.
 */
export async function saveSendLogResendJob(
  db: SqliteExecutor,
  job: SendLogResendJob,
  createdAt: number
): Promise<void> {
  await db.run(
    `INSERT INTO send_log_resend_job (job_id, client_message_id, requester_user_id,
       requester_device_id, retry_id, request_envelope_id, failed_envelope_id, created_at,
       attempts, state)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (job_id) DO UPDATE SET
       client_message_id = excluded.client_message_id,
       requester_user_id = excluded.requester_user_id,
       requester_device_id = excluded.requester_device_id,
       retry_id = excluded.retry_id,
       request_envelope_id = excluded.request_envelope_id,
       failed_envelope_id = excluded.failed_envelope_id,
       attempts = excluded.attempts,
       state = excluded.state`,
    [
      job.jobId,
      job.clientMessageId,
      job.requesterUserId,
      job.requesterDeviceId,
      job.retryId,
      job.requestEnvelopeId,
      job.failedEnvelopeId ?? null,
      createdAt,
      job.attempts,
      job.state,
    ]
  );
}

export async function getSendLogResendJob(
  db: SqliteExecutor,
  jobId: string
): Promise<SendLogResendJob | null> {
  const row = await db.first<SendLogResendJobRow>(
    `SELECT ${SEND_LOG_RESEND_JOB_COLUMNS} FROM send_log_resend_job WHERE job_id = ? LIMIT 1`,
    [jobId]
  );
  return row ? resendJobFromRow(row) : null;
}

export async function getPendingSendLogResendJobs(db: SqliteExecutor): Promise<SendLogResendJob[]> {
  const rows = await db.all<SendLogResendJobRow>(
    `SELECT ${SEND_LOG_RESEND_JOB_COLUMNS} FROM send_log_resend_job
     WHERE state = 'pending' ORDER BY created_at, job_id`
  );
  return rows.map(resendJobFromRow);
}

export async function setSendLogResendJobState(
  db: SqliteExecutor,
  jobId: string,
  state: Exclude<SendLogResendJobState, 'pending'>
): Promise<number> {
  return db.run('UPDATE send_log_resend_job SET state = ? WHERE job_id = ?', [state, jobId]);
}
