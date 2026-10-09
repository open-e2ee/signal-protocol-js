/**
 * Client Constants
 *
 * Shared constants for SignalProtocolClient and related modules.
 */

import { ContentHint } from '../types/messages';

/**
 * 14-day TTL for MessageRecords (SESAME spec Section 6.2)
 *
 * A retry request is unlikely to need a message older than this, so `stop()`
 * discards it. Two call sites use this value:
 * - handleRetryRequestAndResend() to reject expired messages
 * - stop() to clean up old MessageRecords
 */
export {};
export const MESSAGE_RECORD_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

/**
 * Maximum retry responses per message
 *
 * Prevents infinite retry loops when decryption consistently fails.
 * After this many resend attempts for a single message, further retry
 * requests are silently dropped.
 *
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
