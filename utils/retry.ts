/**
 * Retry Utility for Signal Protocol Operations
 *
 * Provides retry logic with exponential backoff for transient failures.
 * Distinguishes between retryable (network, timeout) and non-retryable (crypto) errors.
 *
 * This module is package-local on purpose. The Signal Protocol package must not
 * depend on the app retry layer.
 */

import { EncryptionErrorCode } from '../types';

/**
 * Signal Protocol retry configuration
 *
 * Uses the same parameter names as the unified retry module for consistency.
 */
export {};
export interface SignalProtocolRetryConfig {
  /** Maximum retries (not including initial attempt). Default: 2 (3 total attempts) */
  maxRetries?: number;
  /** Base delay in ms before first retry. Default: 1000 */
  baseDelay?: number;
  /** Enable jitter to prevent thundering herd. Default: true */
  enableJitter?: boolean;
  /** Maximum delay cap in ms. Default: 10000 */
  maxDelay?: number;
  /** Operation name for logging */
  operationName?: string;
}

const SIGNAL_RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 10000,
  backoffMultiplier: 2,
  enableJitter: true,
};

/**
 * Errors that should not be retried (terminal failures)
 *
 * The second group are session-establishment failures. They reach this
 * classifier because a failed device now surfaces its error from inside the
 * retry callback, so a code that is permanent for the life of the request must
 * be listed here or it is attempted three times for no benefit:
 *
 * - UNTRUSTED_IDENTITY and SIGNATURE_VERIFICATION_FAILED are security events.
 *   They want a safety-number check, not another attempt, and retrying only
 *   delays the signal reaching the caller.
 * - RECIPIENT_NOT_REGISTERED means the peer published no prekey bundle. That
 *   cannot become true between two attempts 500 ms apart.
 * - PREKEY_FETCH_RATE_LIMITED is the server defending against prekey drainage.
 *   Retrying into it is the one response guaranteed to make it worse.
 */
const NON_RETRYABLE_ERROR_CODES = new Set([
  EncryptionErrorCode.INVALID_PREKEY_BUNDLE,
  EncryptionErrorCode.SESSION_CONFLICT,
  EncryptionErrorCode.ENCRYPTION_FAILED,
  EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES,
  EncryptionErrorCode.IDENTITY_KEY_CHANGED,
  EncryptionErrorCode.KEY_STORAGE_ERROR,

  EncryptionErrorCode.UNTRUSTED_IDENTITY,
  EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED,
  EncryptionErrorCode.RECIPIENT_NOT_REGISTERED,
  EncryptionErrorCode.PREKEY_FETCH_RATE_LIMITED,
]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function calculateBackoffDelay(
  attempt: number,
  baseDelay: number,
  maxDelay: number,
  backoffMultiplier: number,
  enableJitter: boolean
): number {
  let delay = Math.min(baseDelay * Math.pow(backoffMultiplier, attempt), maxDelay);
  if (enableJitter) {
    delay -= Math.random() * delay * 0.25;
  }
  return Math.floor(delay);
}

function isNetworkError(error: unknown): boolean {
  if (!error) return false;
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  return [
    'network',
    'fetch',
    'connection',
    'timeout',
    'econnrefused',
    'enotfound',
    'enetunreach',
    'etimedout',
    'socket',
  ].some((pattern) => message.includes(pattern));
}

function isDatabaseLockError(error: unknown): boolean {
  if (!error) return false;
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  return (
    message.includes('lock') || message.includes('busy') || message.includes('database is locked')
  );
}

function isRaceConditionError(error: unknown): boolean {
  if (!error) return false;
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  return message.includes('race') || message.includes('concurrent') || message.includes('conflict');
}

/**
 * Check if an error is retryable for Signal Protocol operations
 *
 * Non-retryable:
 * - Encryption error codes (invalid prekey, session conflict, etc.)
 *
 * Retryable:
 * - Network/timeout errors
 * - Database lock errors
 * - Race condition errors
 * - Unknown errors (conservative approach)
 */
export function isRetryableError(error: Error): boolean {
  const code = 'code' in error ? (error as { code?: unknown }).code : undefined;

  // Check for encryption error codes
  if (typeof code === 'string' && NON_RETRYABLE_ERROR_CODES.has(code as EncryptionErrorCode)) {
    return false;
  }

  // Network/timeout errors are retryable
  if (isNetworkError(error)) {
    return true;
  }

  // Database lock errors are retryable
  if (isDatabaseLockError(error)) {
    return true;
  }

  // Race condition errors are retryable
  if (isRaceConditionError(error)) {
    return true;
  }

  // Default: retry unknown errors (conservative approach)
  return true;
}

/**
 * Execute an operation with retry logic
 *
 * @param fn - Async function to execute
 * @param config - Retry configuration
 * @returns Result of the operation
 * @throws Last error if all retries fail
 *
 * @example
 * ```typescript
 * const result = await withRetry(
 *   async () => {
 *     return await fetchPreKeyBundle(userId);
 *   },
 *   { operationName: 'fetchPreKeyBundle', maxRetries: 2 }
 * );
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: SignalProtocolRetryConfig = {}
): Promise<T> {
  const {
    maxRetries = 2,
    baseDelay = 1000,
    enableJitter = true,
    maxDelay = 10000,
    operationName = 'unknown operation',
  } = config;

  const totalAttempts = maxRetries + 1;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < totalAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const normalizedError =
        error instanceof Error ? error : new Error(`${operationName} failed: ${String(error)}`);
      lastError = normalizedError;

      if (attempt === totalAttempts - 1 || !isRetryableError(normalizedError)) {
        break;
      }

      const delay = calculateBackoffDelay(
        attempt,
        baseDelay,
        maxDelay,
        SIGNAL_RETRY_CONFIG.backoffMultiplier,
        enableJitter
      );
      await sleep(delay);
    }
  }

  throw lastError ?? new Error(`${operationName} failed after retry exhaustion`);
}
