/**
 * Retry Request Utilities
 *
 * Utility functions for SESAME retry request handling.
 * Extracted for testability and reuse.
 *
 */

import { EncryptionError, EncryptionErrorCode } from '../types/errors';
import { RetryReason } from '../internal/sesame/types';
import type { ContentHint } from '../types/messages';
import type { SenderKeyStore } from '../types/api';
import type { Base64 } from '../types/utils';
import { base64ToBytes } from '../internal/crypto/utils';
import { extractGroupId } from '../internal/groups/group-id';
import { resolveGroupForFramedMessage } from '../internal/protocol/sender-keys/manager';
import type { RetryRequestSource } from './retry-request-lifecycle';

/**
 * Determine the appropriate retry reason based on error type
 *
 * Maps EncryptionError codes to SESAME RetryReason values.
 * Used when creating retry requests for failed decryptions.
 *
 * @param error - The error that caused decryption to fail
 * @returns The appropriate RetryReason for the retry request
 */
export {};
export function determineRetryReason(error: Error): RetryReason {
  if (error instanceof EncryptionError) {
    switch (error.code) {
      case EncryptionErrorCode.SESSION_NOT_FOUND:
        return RetryReason.NO_SESSION;
      case EncryptionErrorCode.SESSION_CORRUPTED:
      case EncryptionErrorCode.DECRYPTION_FAILED:
      case EncryptionErrorCode.INVALID_CIPHERTEXT:
      case EncryptionErrorCode.PREKEY_NOT_FOUND:
        // PREKEY_NOT_FOUND maps to DECRYPTION_FAILED because the sender
        // needs to fetch a fresh prekey bundle and create a new session.
        // This happens after device reinstall when sender used stale bundle.
        return RetryReason.DECRYPTION_FAILED;
      case EncryptionErrorCode.UNTRUSTED_IDENTITY:
        return RetryReason.IDENTITY_KEY_MISMATCH;
      case EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES:
        return RetryReason.SESSION_EXPIRED;
      default:
        return RetryReason.DECRYPTION_FAILED;
    }
  }
  // For non-EncryptionErrors, default to generic decryption failure
  return RetryReason.DECRYPTION_FAILED;
}

/**
 * Check if an error represents an expected "needs retry" case.
 *
 * These are errors that trigger the SESAME retry flow - they are not
 * unexpected failures but rather expected recovery scenarios:
 * - Session too old (MAXRECV exceeded)
 * - No session found
 * - Session expired
 *
 * Note: an identity change (UNTRUSTED_IDENTITY) is NOT included here. It is a
 * security event that should log at ERROR level and require user verification
 * of safety numbers. A retry request is still sent for it, but it warrants
 * higher visibility logging.
 *
 * Expected retry cases should be logged at INFO level, not ERROR,
 * since they are part of the normal recovery flow per SESAME spec §6.2.
 *
 * @param error - The error to check
 * @returns true if this is an expected retry case, false if unexpected failure
 */
export function isRetryableDecryptionError(error: Error): boolean {
  // Check for SesameError codes directly (nested in EncryptionError.context)
  const errorMessage = error.message.toLowerCase();
  const sesameRetryPatterns = [
    'session_too_old_to_receive',
    'too old to receive',
    'maxrecv',
    'no_session',
    'session not found',
    'session_expired',
  ];

  if (sesameRetryPatterns.some((pattern) => errorMessage.includes(pattern))) {
    return true;
  }

  // Check EncryptionError codes that trigger expected retries
  if (error instanceof EncryptionError) {
    const retryableCodes = [
      EncryptionErrorCode.SESSION_NOT_FOUND,
      EncryptionErrorCode.SESSION_CORRUPTED,
      EncryptionErrorCode.DECRYPTION_FAILED,
      EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES,
      // PREKEY_NOT_FOUND is expected after device reinstall when sender
      // used a stale prekey bundle. The retry flow will fix this by having
      // the sender fetch a fresh bundle with our current prekeys.
      EncryptionErrorCode.PREKEY_NOT_FOUND,
    ];
    return retryableCodes.includes(error.code);
  }

  // Check nested originalError for SesameError
  const contextError =
    typeof error === 'object' &&
    error !== null &&
    'context' in error &&
    typeof error.context === 'object' &&
    error.context !== null &&
    'originalError' in error.context
      ? (error.context.originalError as { message?: string; code?: string } | undefined)
      : undefined;
  if (contextError) {
    const nestedMessage = contextError.message?.toLowerCase() || '';
    const nestedCode = contextError.code?.toLowerCase() || '';
    if (
      sesameRetryPatterns.some(
        (pattern) => nestedMessage.includes(pattern) || nestedCode.includes(pattern)
      )
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Describe a failed envelope for its retry request, the same on every
 * receive path. A `sender_key` envelope is a group message: its request
 * carries no ratchet key, and its request record stores it as a group
 * message, so a resend that brings only the sender key does not fulfill it.
 * The envelope names no group. Its group is known only when the local
 * sender key store holds the distribution that the frame names, as
 * `resolveGroupForFramedMessage` tells, and the record then stores it in
 * the form that `DecryptedEnvelope.conversationId` uses. A missing sender
 * key gives no group. The content hint, which travels inside a seal, sets
 * when the client reports the delivery error of the envelope.
 *
 * @param store - The sender key store of the local device
 * @param envelope - The failed envelope, after any unseal
 * @returns What the failed envelope names for `requestRetryInFamily`
 */
export async function retryFailedEnvelope(
  store: Pick<SenderKeyStore, 'resolveGroupForSenderKeyId'>,
  envelope: {
    readonly messageType?: string;
    readonly clientMessageId?: string;
    readonly contentHint?: ContentHint;
    readonly senderUserId: string;
    readonly senderDeviceId: number;
    readonly ciphertext: string | Uint8Array;
  }
): Promise<NonNullable<RetryRequestSource['failedEnvelope']>> {
  const groupMessage = envelope.messageType === 'sender_key';
  const groupId = groupMessage ? await failedEnvelopeGroup(store, envelope) : null;
  return {
    ...(envelope.clientMessageId !== undefined && { clientMessageId: envelope.clientMessageId }),
    ...(envelope.contentHint !== undefined && { contentHint: envelope.contentHint }),
    senderKey: groupMessage,
    groupMessage,
    ...(groupId !== null && { groupId }),
  };
}

/** The group of a failed sender-key envelope, or null when the store does not know it. */
async function failedEnvelopeGroup(
  store: Pick<SenderKeyStore, 'resolveGroupForSenderKeyId'>,
  envelope: {
    readonly senderUserId: string;
    readonly senderDeviceId: number;
    readonly ciphertext: string | Uint8Array;
  }
): Promise<string | null> {
  let framed: Uint8Array;
  try {
    framed =
      typeof envelope.ciphertext === 'string'
        ? base64ToBytes(envelope.ciphertext as Base64)
        : envelope.ciphertext;
  } catch {
    // A malformed envelope names no group.
    return null;
  }
  const groupId = await resolveGroupForFramedMessage(
    store,
    framed,
    envelope.senderUserId,
    envelope.senderDeviceId
  );
  return groupId === null ? null : extractGroupId(groupId);
}
