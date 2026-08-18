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
 * Envelope types that take ContentHint.Implicit behavior.
 * Server-generated receipts are implicit. Client-to-client implicit types
 * (typing indicators, delivery receipts) use ContentHint.Implicit on the envelope.
 */
export const IMPLICIT_ENVELOPE_TYPES = ['server_delivery_receipt'] as const;

/**
 * Check if a message takes ContentHint.Implicit behavior.
 *
 * Implicit messages are ephemeral (typing indicators, receipts) and should be
 * silently discarded on decryption failure - no ERROR logs, no retry requests.
 *
 * The primary mechanism is ContentHint.Implicit (set by the sender on the envelope).
 * Server-generated delivery receipts are also implicit by envelope type.
 *
 * @param envelope - Message envelope with optional contentHint and messageType
 * @returns true if the message is implicit, and the caller should discard it
 * on failure
 */
export function isImplicitContentType(envelope: {
  contentHint?: ContentHint;
  messageType?: string;
}): boolean {
  return (
    envelope.contentHint === ContentHint.Implicit ||
    (envelope.messageType !== undefined &&
      IMPLICIT_ENVELOPE_TYPES.includes(
        envelope.messageType as (typeof IMPLICIT_ENVELOPE_TYPES)[number]
      ))
  );
}
