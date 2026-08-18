/**
 * Retry Request Utilities
 *
 * Utility functions for SESAME retry request handling.
 * Extracted for testability and reuse.
 *
 */

import { EncryptionError, EncryptionErrorCode } from '../types/errors';
import { RetryReason } from '../internal/sesame/types';

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
