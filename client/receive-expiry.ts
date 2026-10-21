/**
 * The age rule of the receive queue (outcome 3).
 *
 * A receive record expires when it waited `MAX_RECEIVE_WORK_AGE_MS`, 30
 * days, since its first durable admission on this device. The age uses wall
 * time. A negative age, after the clock moved back, counts as 0. A clock
 * that moves forward can expire a record early.
 *
 * The rule reads only the age. It never reads the retry deadline of the
 * retry request lifecycle, the content recovery retention, or the sender
 * key rotation.
 */

import type { ReceiveWorkRecord } from '../types/api';
import { MAX_RECEIVE_WORK_AGE_MS } from './constants';

/**
 * Tell whether a receive record has expired.
 *
 * @param record - The record. Its `receivedAt` is the time of the first
 *   durable admission, and no later write changes it.
 * @param now - The current wall time.
 * @param maxAgeMs - The age. Only a test passes a value other than
 *   `MAX_RECEIVE_WORK_AGE_MS`.
 */
export function isReceiveExpired(
  record: Pick<ReceiveWorkRecord, 'receivedAt'>,
  now: number,
  maxAgeMs: number = MAX_RECEIVE_WORK_AGE_MS
): boolean {
  return Math.max(0, now - record.receivedAt) >= maxAgeMs;
}

/**
 * The time at which a receive record expires.
 *
 * @param maxAgeMs - The age. Only a test passes a value other than
 *   `MAX_RECEIVE_WORK_AGE_MS`.
 */
export function receiveExpiresAt(
  record: Pick<ReceiveWorkRecord, 'receivedAt'>,
  maxAgeMs: number = MAX_RECEIVE_WORK_AGE_MS
): number {
  return record.receivedAt + maxAgeMs;
}
