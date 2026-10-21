/**
 * The order in which a send log store returns its rows. The SQLite stores
 * sort in SQL. The other stores sort with these comparators, so every
 * adapter returns the same order.
 */

import type { SendLogDevice, SendLogEntry, SendLogResendJob } from '../../types/api';

/** Order strings by UTF-16 code unit, as SQLite's binary collation orders ASCII text. */
export function compareText(left: string, right: string): number {
  if (left < right) return -1;
  return left > right ? 1 : 0;
}

/** Recipient rows: by user, then by device number. */
export function compareSendLogDevices(left: SendLogDevice, right: SendLogDevice): number {
  return compareText(left.userId, right.userId) || left.deviceId - right.deviceId;
}

/** Entries of one device: by the ID of the send. */
export function compareSendLogEntries(left: SendLogEntry, right: SendLogEntry): number {
  return compareText(left.payload.clientMessageId, right.payload.clientMessageId);
}

/** Resend jobs: by the time the store first wrote them, then by job ID. */
export function compareResendJobs(left: SendLogResendJob, right: SendLogResendJob): number {
  return left.createdAt - right.createdAt || compareText(left.jobId, right.jobId);
}
