/**
 * Error type definitions for Signal Protocol.
 *
 * Every error the SDK throws is an `EncryptionError` carrying an
 * `EncryptionErrorCode`. A subclass exists only where the caller needs typed
 * data off the error to recover. Examples are the peer's address and identity
 * to verify a safety number, and the counter and epoch of a duplicate. Each
 * subclass fixes its own code in its constructor.
 *
 * ```
 * Error
 *   └── EncryptionError            code + context, thrown directly for most failures
 *         ├── UntrustedIdentityError    address + identity, for safety-number verification
 *         ├── DuplicatedMessageError    counter + epoch of the replayed message
 *         ├── SealedSenderAuthError     the rejected sealed-sender credential
 *         ├── PQXDHRequiredError        which post-quantum key the peer is missing
 *         └── StorageQuotaExceededError the store that ran out of room
 * ```
 *
 * A code or a subclass belongs here only if production code can produce it. An
 * error-surface check in the engineering repository parses for the construction
 * sites that decide that. It fails the build when this module declares
 * something nothing throws. A `switch` arm or a non-retryable set only reads a
 * code. It does not produce one, so it does not keep a code alive.
 */

import type { ProtocolAddress } from './address';
import type { CompositeIdentityV1, PublicKey } from '../keys';

/**
 * Context information for encryption errors.
 *
 * Provides additional details about where and why an error occurred,
 * making debugging and user messaging easier.
 */
export {};
export interface EncryptionErrorContext {
  /** The protocol address involved in the error (if applicable) */
  address?: ProtocolAddress;

  /** The operation in progress when the error occurred */
  operation?: string;

  /** The identity key involved (for trust/verification errors) */
  identityKey?: PublicKey;
  identity?: CompositeIdentityV1;

  /** The underlying cause of the error */
  originalError?: Error;

  /** Additional context-specific data */
  [key: string]: unknown;
}

/**
 * Base encryption error class.
 *
 * Enhanced with context support for better error handling and debugging.
 * Provides error patterns.
 *
 * @example
 * ```typescript
 * throw new EncryptionError(
 *   'Session not found',
 *   EncryptionErrorCode.SESSION_NOT_FOUND,
 *   { address, operation: 'encryptMessage' }
 * );
 * ```
 */
export class EncryptionError extends Error {
  constructor(
    message: string,
    public code: EncryptionErrorCode,
    public context?: EncryptionErrorContext
  ) {
    super(message);
    this.name = 'EncryptionError';

    // Maintain Error's stack trace for debugging
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EncryptionError);
    }
  }

  /** Get the protocol address from context if available */
  get address(): ProtocolAddress | undefined {
    return this.context?.address;
  }

  /** Get the operation from context if available */
  get operation(): string | undefined {
    return this.context?.operation;
  }

  /** Get the underlying error from context if available */
  get originalError(): Error | undefined {
    return this.context?.originalError;
  }
}

/**
 * Stable encryption error codes for programmatic handling.
 *
 * Organized by category for better error handling and user messaging.
 * Provides extensive error code set.
 *
 */
export enum EncryptionErrorCode {
  // ===== Session Errors =====

  /** Session not found for the given address */
  SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',

  /** Damaged or invalid session data */
  SESSION_CORRUPTED = 'SESSION_CORRUPTED',

  /**
   * Recipient has not registered encryption keys.
   *
   * The target user has no prekey bundle available on the server.
   * Their encryption setup may be incomplete.
   */
  RECIPIENT_NOT_REGISTERED = 'RECIPIENT_NOT_REGISTERED',

  /**
   * Rate limited - too many prekey bundle fetches.
   *
   * Server enforces rate limits to prevent prekey drainage attacks.
   */
  PREKEY_FETCH_RATE_LIMITED = 'PREKEY_FETCH_RATE_LIMITED',

  /**
   * Session establishment failed after retries.
   *
   * Could not establish a session with the recipient after
   * multiple attempts. May indicate network issues.
   */
  SESSION_ESTABLISHMENT_FAILED = 'SESSION_ESTABLISHMENT_FAILED',

  // ===== Message Errors =====

  /** Message ciphertext is invalid or malformed */
  INVALID_CIPHERTEXT = 'INVALID_CIPHERTEXT',

  /** Message decryption failed */
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',

  /** Message encryption failed */
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',

  /**
   * Duplicate message detected (replay attack).
   *
   * The session already processed this message number.
   */
  MESSAGE_DUPLICATE = 'MESSAGE_DUPLICATE',

  /**
   * Too many messages skipped (DoS protection).
   *
   * Prevents attackers from forcing storage of excessive message keys.
   * Signal Protocol Section 8.4 recommends limiting skipped messages.
   */
  TOO_MANY_SKIPPED_MESSAGES = 'TOO_MANY_SKIPPED_MESSAGES',

  /**
   * Replay attack detected: envelope.timestamp does not match dataMessage.timestamp.
   *
   * After decryption, the envelope timestamp must match the timestamp inside the encrypted
   * content. A mismatch indicates an attacker may have re-sent old encrypted content
   * with manipulated envelope metadata.
   *
   */
  REPLAY_DETECTED = 'REPLAY_DETECTED',

  /**
   * The sender key expired under the time-based rotation policy.
   *
   * The default policy rotates sender keys every two weeks.
   * The caller should auto-rotate the sender key and redistribute to group members.
   */
  SENDER_KEY_EXPIRED = 'SENDER_KEY_EXPIRED',

  // ===== Identity & Trust Errors =====

  /**
   * Identity key is not trusted.
   *
   * The user did not verify the identity, or the identity changed without
   * confirmation.
   */
  UNTRUSTED_IDENTITY = 'UNTRUSTED_IDENTITY',

  /**
   * Sender identity mismatch.
   *
   * The sender address in the message does not match the expected address.
   * This indicates a session hijacking attempt where an attacker tries to
   * inject their messages under a different identity.
   */
  IDENTITY_MISMATCH = 'IDENTITY_MISMATCH',

  /** Signature verification failed */
  SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',

  // ===== PreKey & Session Establishment Errors =====

  /** PreKey bundle is invalid or malformed */
  INVALID_PREKEY_BUNDLE = 'INVALID_PREKEY_BUNDLE',

  /** PreKey not found */
  PREKEY_NOT_FOUND = 'PREKEY_NOT_FOUND',

  /**
   * PreKey rotation required before sending.
   *
   * Signed prekeys or Kyber prekeys are past the maximum allowed age
   * (14 days by default). The client blocks message sending until rotation
   * succeeds, which maintains the forward-secrecy guarantees.
   *
   * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
   */
  PREKEY_ROTATION_REQUIRED = 'PREKEY_ROTATION_REQUIRED',

  // ===== Ratchet Errors =====

  /**
   * Message counter overflow.
   *
   * The counter reached MAX_SAFE_INTEGER, so the caller must rotate the session.
   * This is a safety check to prevent cryptographic issues from counter wrap-around.
   */
  COUNTER_OVERFLOW = 'COUNTER_OVERFLOW',

  /**
   * Invalid DH public key.
   *
   * A malformed DH public key, or one that fails validation.
   */
  INVALID_DH_KEY = 'INVALID_DH_KEY',

  // ===== Storage Errors =====

  /** Key storage operation failed */
  KEY_STORAGE_ERROR = 'KEY_STORAGE_ERROR',

  /**
   * The storage backend rejected a write because the origin ran out of
   * storage quota.
   *
   * The rejected write did not persist. Storage adapters commit each
   * write in an atomic transaction, so quota exhaustion rolls the whole
   * transaction back instead of leaving a subset. The application should
   * free space or request more from the platform, then retry.
   */
  STORAGE_QUOTA_EXCEEDED = 'STORAGE_QUOTA_EXCEEDED',

  // ===== Initialization Errors =====

  /** Signal Protocol initialization failed */
  INITIALIZATION_FAILED = 'INITIALIZATION_FAILED',

  // ===== Protocol Strategy Errors =====

  /**
   * PQXDH (post-quantum key exchange) applies, but the partner lacks Kyber keys.
   *
   * Thrown when partner does not support the required PQXDH handshake.
   * Application can catch this to notify user or queue message for retry.
   */
  PQXDH_REQUIRED = 'PQXDH_REQUIRED',

  /**
   * PQXDH key exchange failed during handshake.
   *
   * The post-quantum key exchange encountered an error. The SDK aborts the
   * session instead of a downgrade to classical X3DH.
   */
  PQXDH_FAILED = 'PQXDH_FAILED',

  /**
   * Triple Ratchet applies, but the session did not use PQXDH.
   *
   * Triple Ratchet requires post-quantum material from PQXDH.
   * Cannot enable Triple Ratchet with classical X3DH handshake.
   */
  TRIPLE_RATCHET_REQUIRED = 'TRIPLE_RATCHET_REQUIRED',

  // ===== SPQR (Sparse Post-Quantum Ratchet) Errors =====

  /**
   * SPQR epoch is out of valid range.
   *
   * Either requesting a future epoch (not yet established) or
   * an epoch too old (chains already cleaned up).
   */
  SPQR_EPOCH_OUT_OF_RANGE = 'SPQR_EPOCH_OUT_OF_RANGE',

  /**
   * Message number jump too large (DoS protection).
   *
   * Prevents attackers from forcing storage of excessive skipped keys.
   * `SPQR`'s the profile uses `max_jump` of 25,000.
   */
  SPQR_MESSAGE_JUMP_TOO_LARGE = 'SPQR_MESSAGE_JUMP_TOO_LARGE',

  /**
   * SPQR message counter overflow.
   *
   * The counter reached its maximum value, so the caller must rotate the epoch.
   */
  SPQR_COUNTER_OVERFLOW = 'SPQR_COUNTER_OVERFLOW',

  /**
   * Invalid Kyber ciphertext in SPQR context.
   *
   * Ciphertext has wrong size or format for ML-KEM-1024.
   */
  SPQR_INVALID_CIPHERTEXT = 'SPQR_INVALID_CIPHERTEXT',

  /**
   * SPQR version negotiation failed.
   *
   * Peer's maximum supported version is below our minimum required version.
   * For example, peer only supports V0 but we require V1.
   */
  SPQR_VERSION_MISMATCH = 'SPQR_VERSION_MISMATCH',

  // ===== Sealed Sender Errors =====

  /**
   * Sealed sender authentication failed.
   *
   * The server rejected the unidentified access key. This may trigger
   * fallback to identified sender delivery.
   */
  SEALED_SENDER_AUTH_FAILED = 'SEALED_SENDER_AUTH_FAILED',

  // ===== Generic Errors =====

  /** Invalid operation or state */
  INVALID_STATE = 'INVALID_STATE',
}

// ===== Specialized Error Classes =====

/**
 * Error thrown when an identity key is not trusted.
 *
 * This is a security-critical error that requires user intervention.
 * The user must verify the safety number before continuing communication.
 *
 * @example
 * ```typescript
 * throw new UntrustedIdentityError(address, identityKey);
 * ```
 */
export class UntrustedIdentityError extends EncryptionError {
  public readonly untrustedAddress: ProtocolAddress;
  public readonly identity: CompositeIdentityV1;

  constructor(address: ProtocolAddress, identity: CompositeIdentityV1) {
    super(
      `Untrusted identity for ${address.userId}.${address.deviceId}`,
      EncryptionErrorCode.UNTRUSTED_IDENTITY,
      { address, identity }
    );
    this.name = 'UntrustedIdentityError';
    this.untrustedAddress = address;
    this.identity = identity;
  }
}

/**
 * Error thrown when the session detects a duplicate message (replay attack).
 *
 * This is a security-critical error indicating:
 * - Network replay (attacker re-sent a captured message)
 * - Client bug (accidentally decrypting same message twice)
 * - Storage corruption (a damaged message key index)
 *
 * Metadata should support diagnostics without exposing secret material.
 *
 * @example
 * ```typescript
 * throw new DuplicatedMessageError(address, { counter: 5, epoch: 0 });
 * ```
 */
export class DuplicatedMessageError extends EncryptionError {
  public readonly duplicatedAddress: ProtocolAddress;
  /** The duplicate message counter (if known) - matches the reference implementation's proto field name */
  public readonly counter?: number;
  /** Epoch (for Triple Ratchet) of the duplicate */
  public readonly epoch?: number;
  /** Fingerprint of the duplicate ciphertext (truncated for logging) */
  public readonly fingerprintPreview?: string;

  constructor(
    address: ProtocolAddress,
    metadata?: {
      counter?: number;
      epoch?: number;
      fingerprintPreview?: string;
    }
  ) {
    super(
      `Duplicate message detected for ${address.userId}.${address.deviceId}${
        metadata?.counter !== undefined ? ` (msg #${metadata.counter})` : ''
      }`,
      EncryptionErrorCode.MESSAGE_DUPLICATE,
      {
        address,
        counter: metadata?.counter,
        epoch: metadata?.epoch,
      }
    );
    this.name = 'DuplicatedMessageError';
    this.duplicatedAddress = address;
    this.counter = metadata?.counter;
    this.epoch = metadata?.epoch;
    this.fingerprintPreview = metadata?.fingerprintPreview;
  }
}

/**
 * Type guard to check if an error is a DuplicatedMessageError.
 *
 * @param error - Error to check
 * @returns true if error is DuplicatedMessageError
 */
export function isDuplicatedMessageError(error: unknown): error is DuplicatedMessageError {
  return error instanceof DuplicatedMessageError;
}

/**
 * Error thrown when sealed sender (anonymous delivery) authentication fails.
 *
 * The server rejected the unidentified access key, for one of these reasons:
 * - The access key does not match the recipient's stored key
 * - The recipient's account was not found
 * - The recipient disabled unrestricted unidentified access
 *
 * This error triggers automatic fallback to identified sender delivery.
 *
 * @example
 * ```typescript
 * try {
 *   await relay.sendUnidentified(envelope, accessKey);
 * } catch (error) {
 *   if (isSealedSenderAuthError(error)) {
 *     // Fall back to identified delivery
 *     await relay.send(envelope);
 *   }
 * }
 * ```
 */
export class SealedSenderAuthError extends EncryptionError {
  constructor(cause?: Error) {
    super('Sealed sender authentication failed', EncryptionErrorCode.SEALED_SENDER_AUTH_FAILED, {
      operation: 'sendUnidentified',
      originalError: cause,
    });
    this.name = 'SealedSenderAuthError';
  }
}

/**
 * Type guard to check if an error is a SealedSenderAuthError.
 *
 * @param error - Error to check
 * @returns true if error is SealedSenderAuthError
 */
export function isSealedSenderAuthError(error: unknown): error is SealedSenderAuthError {
  return error instanceof SealedSenderAuthError;
}

/**
 * Fallback type categories for PQXDH errors.
 *
 * Distinguishes between different types of fallback scenarios:
 * - `missing_keys`: Partner does not have Kyber prekeys (expected compatibility issue)
 * - `crypto_failure`: Kyber operation failed (decapsulation, signature, etc.)
 * - `protocol_mismatch`: Version or format incompatibility
 */
export type PQXDHFallbackType = 'missing_keys' | 'crypto_failure' | 'protocol_mismatch';

/**
 * Options for PQXDHRequiredError constructor.
 */
export interface PQXDHRequiredErrorOptions {
  /** Whether the caller can retry the operation (e.g., after partner updates keys) */
  retryable?: boolean;
  /** Suggested delay before retry in milliseconds */
  suggestedRetryDelay?: number;
  /** Category of fallback for analytics and handling */
  fallbackType?: PQXDHFallbackType;
  /** The underlying error that caused the failure */
  originalError?: Error;
}

/**
 * Error thrown when PQXDH applies, but the partner lacks Kyber keys.
 *
 * This is a recoverable error - applications can:
 * - Notify user that partner needs to update their app
 * - Queue the message for retry when partner uploads Kyber prekeys
 * - Fall back to classical encryption with user consent
 *
 * Recovery metadata:
 * - `retryable`: Whether the caller can retry the operation
 * - `suggestedRetryDelay`: Recommended delay before retry (ms)
 * - `fallbackType`: Category of fallback for analytics
 *
 * @example Handling in application
 * ```typescript
 * try {
 *   await signal.encryptMessage(sessionId, message);
 * } catch (error) {
 *   if (isPQXDHRequiredError(error)) {
 *     if (error.retryable) {
 *       // Schedule retry with suggested delay
 *       setTimeout(() => retryEncryption(), error.suggestedRetryDelay ?? 5000);
 *     } else if (error.fallbackType === 'missing_keys') {
 *       // Partner doesn't support post-quantum yet
 *       showDialog({
 *         title: 'Enhanced Security Unavailable',
 *         message: `${error.remoteAddress} needs to update their app.`,
 *         actions: [
 *           { label: 'Queue Message', action: () => queueForRetry(message) },
 *           { label: 'Send Anyway', action: () => sendWithClassical(message) }
 *         ]
 *       });
 *     }
 *   }
 * }
 * ```
 */
export class PQXDHRequiredError extends EncryptionError {
  public readonly remoteAddress: string;
  public readonly reason: 'no_kyber_prekey' | 'pqxdh_failed';
  /** Whether the caller can retry the operation */
  public readonly retryable: boolean;
  /** Suggested delay before retry in milliseconds */
  public readonly suggestedRetryDelay?: number;
  /** Category of fallback for analytics and handling */
  public readonly fallbackType: PQXDHFallbackType;

  constructor(
    remoteAddress: string,
    reason: 'no_kyber_prekey' | 'pqxdh_failed',
    options?: PQXDHRequiredErrorOptions
  ) {
    const opts: PQXDHRequiredErrorOptions = options ?? {};

    const message =
      reason === 'no_kyber_prekey'
        ? `Partner ${remoteAddress} does not have Kyber prekeys - post-quantum encryption unavailable`
        : `PQXDH key exchange failed with ${remoteAddress} - post-quantum encryption unavailable`;

    super(
      message,
      reason === 'no_kyber_prekey'
        ? EncryptionErrorCode.PQXDH_REQUIRED
        : EncryptionErrorCode.PQXDH_FAILED,
      { operation: 'keyAgreement', originalError: opts.originalError }
    );
    this.name = 'PQXDHRequiredError';
    this.remoteAddress = remoteAddress;
    this.reason = reason;

    // Set recovery metadata with sensible defaults
    this.fallbackType =
      opts.fallbackType ?? (reason === 'no_kyber_prekey' ? 'missing_keys' : 'crypto_failure');
    this.retryable = opts.retryable ?? reason === 'no_kyber_prekey'; // The caller can retry missing keys after partner updates
    this.suggestedRetryDelay = opts.suggestedRetryDelay ?? (this.retryable ? 30000 : undefined); // 30s default for retryable
  }
}

/**
 * Error thrown when the storage backend rejects a write because the origin
 * ran out of storage quota.
 *
 * The rejected write did not persist. Storage adapters commit each write
 * in an atomic transaction, so quota exhaustion rolls the whole
 * transaction back instead of leaving a subset. The application should
 * free space or request more from the platform, then retry the write.
 *
 * @example
 * ```typescript
 * try {
 *   await store.storeSessionRecord(address, record);
 * } catch (error) {
 *   if (error instanceof StorageQuotaExceededError) {
 *     await promptUserToFreeSpace();
 *   }
 * }
 * ```
 */
export class StorageQuotaExceededError extends EncryptionError {
  constructor(operation: string, originalError?: Error) {
    super(
      `Storage quota exceeded during ${operation}`,
      EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED,
      { operation, originalError }
    );
    this.name = 'StorageQuotaExceededError';
  }
}

/**
 * Type guard to check if an error is a StorageQuotaExceededError.
 *
 * @param error - Error to check
 * @returns true if error is StorageQuotaExceededError
 */
export function isStorageQuotaExceededError(
  error: unknown
): error is StorageQuotaExceededError {
  return error instanceof StorageQuotaExceededError;
}

/**
 * Type guard to check if an error is a PQXDHRequiredError.
 *
 * @param error - Error to check
 * @returns true if error is PQXDHRequiredError
 */
export function isPQXDHRequiredError(error: unknown): error is PQXDHRequiredError {
  return error instanceof PQXDHRequiredError;
}

/**
 * Type guard to check if an error is an UntrustedIdentityError.
 *
 * @param error - Error to check
 * @returns true if error is UntrustedIdentityError
 */
export function isUntrustedIdentityError(error: unknown): error is UntrustedIdentityError {
  return error instanceof UntrustedIdentityError;
}

/**
 * Type guard to check if an error is any Signal Protocol error.
 */
export function isEncryptionError(error: unknown): error is EncryptionError {
  return error instanceof EncryptionError;
}
