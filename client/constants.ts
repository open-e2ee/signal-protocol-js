/**
 * Client Constants
 *
 * Shared constants for SignalProtocolClient and related modules.
 */

import { ContentHint } from '../types/messages';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/**
 * How long a sender keeps resendable content: 14 days.
 *
 * A retry request is unlikely to need a message older than this. The value
 * is Signal's retry answer age and send log lifetime. Three call sites use
 * it:
 * - handleRetryRequestAndResend() rejects an expired message record
 * - create() and stop() delete expired message records
 */
export const RESENDABLE_CONTENT_RETENTION_MS = 14 * DAY_MS;

/**
 * The longest retention that `protocol.contentRecovery.retentionMs` accepts:
 * 30 days, the longest time that the Relay keeps a durable message.
 */
export const MAX_RESENDABLE_CONTENT_RETENTION_MS = 30 * DAY_MS;

/**
 * The time that the receive queue keeps waiting receive work: 30 days from
 * its first durable admission on this device. The age is fixed.
 */
export const MAX_RECEIVE_WORK_AGE_MS = 30 * DAY_MS;

/**
 * The default receive queue bounds. They are provisional until a
 * measurement of real receive queues replaces them.
 */
export const RECEIVE_QUEUE_DEFAULT_MAX_ITEMS = 3_000;
/** 750 MiB of receive records. */
export const RECEIVE_QUEUE_DEFAULT_MAX_BYTES = 786_432_000;
/** The part of the queue bounds that the blocked records of one group can fill. */
export const RECEIVE_QUEUE_DEFAULT_BLOCKED_GROUP_SHARE = 0.25;

/**
 * The previous name of `RESENDABLE_CONTENT_RETENTION_MS`, the lifetime of
 * a MessageRecord (SESAME spec Section 6.2).
 *
 * @deprecated Use `RESENDABLE_CONTENT_RETENTION_MS`.
 */
export const MESSAGE_RECORD_TTL_MS = RESENDABLE_CONTENT_RETENTION_MS;

/**
 * How long a recipient waits for the resend of a resendable message that it
 * could not decrypt before it shows a delivery error: one hour. The error
 * does not end the recovery.
 */
export const RETRY_PLACEHOLDER_DEADLINE_MS = HOUR_MS;

/** How long a sender runs a persisted resend job before it abandons it: one day. */
export const SEND_LOG_RESEND_JOB_TTL_MS = DAY_MS;

/**
 * Maximum retry responses per message
 *
 * Prevents infinite retry loops when decryption consistently fails.
 * After this many resend attempts for a single message, further retry
 * requests are silently dropped. A requester whose resend of this attempt
 * number also fails ends its request as `attempts-exhausted`.
 */
export const MAX_RETRY_RESPONSES_PER_MESSAGE = 5;

/**
 * Check if a message takes ContentHint.Implicit behavior.
 *
 * Implicit messages have disposable content semantics (for example typing
 * indicators and receipts) and should be silently discarded on decryption
 * failure - no ERROR logs, no retry requests. Their Relay delivery class is a
 * separate persistence and wake decision.
 *
 * The sender sets ContentHint.Implicit on the envelope.
 *
 * @param envelope - Message envelope with optional contentHint
 * @returns true if the message is implicit, and the caller should discard it
 * on failure
 */
export function isImplicitContentType(envelope: { contentHint?: ContentHint }): boolean {
  return envelope.contentHint === ContentHint.Implicit;
}
