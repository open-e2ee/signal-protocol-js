/**
 * Error type definitions for Signal Protocol
 *
 * Implements a tiered error system aligned with the layered architecture:
 *
 * ```
 * Layer      Error Class          Use Case
 * ──────────────────────────────────────────────────────
 * Layer 1    CryptoError         Low-level crypto failures
 * Layer 5    SessionError        Session operations
 * Layer 6    ProtocolError       Protocol-level errors
 * Client     ClientError         User-facing errors
 * Base       EncryptionError     Generic encryption errors
 * ```
 *
 * Error Hierarchy:
 * ```
 * Error
 *   └── EncryptionError (base for all Signal Protocol errors)
 *         ├── CryptoError (Layer 1)
 *         ├── SessionError (Layer 5)
 *         ├── ProtocolError (Layer 6)
 *         ├── ClientError (User-facing)
 *         └── Specialized errors (UntrustedIdentityError, etc.)
 * ```
 *
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

  /** The operation being performed when the error occurred */
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

  /** Session data is corrupted or invalid */
  SESSION_CORRUPTED = 'SESSION_CORRUPTED',

  /**
   * Multiple active sessions detected (race condition).
   *
   * Occurs when both parties try to establish sessions simultaneously.
   * Requires session archiving and convergence.
   */
  SESSION_CONFLICT = 'SESSION_CONFLICT',

  /**
   * Recipient has not registered encryption keys.
   *
   * The target user has no prekey bundle available on the server.
   * They may not have completed encryption setup.
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
   * Message number has already been processed.
   */
  MESSAGE_DUPLICATE = 'MESSAGE_DUPLICATE',

  /**
   * Message arrived too old to decrypt.
   *
   * Message keys have been deleted due to age or count limits.
   */
  MESSAGE_TOO_OLD = 'MESSAGE_TOO_OLD',

  /**
   * Too many messages skipped (DoS protection).
   *
   * Prevents attackers from forcing storage of excessive message keys.
   * Signal Protocol Section 8.4 recommends limiting skipped messages.
   */
  TOO_MANY_SKIPPED_MESSAGES = 'TOO_MANY_SKIPPED_MESSAGES',

  /**
   * Replay attack detected: envelope.timestamp doesn't match dataMessage.timestamp.
   *
   * After decryption, the envelope timestamp must match the timestamp inside the encrypted
   * content. A mismatch indicates an attacker may have re-sent old encrypted content
   * with manipulated envelope metadata.
   *
   */
  REPLAY_DETECTED = 'REPLAY_DETECTED',

  /**
   * Invalid message version or protocol mismatch.
   *
   * Message was encrypted with an incompatible protocol version.
   */
  INVALID_MESSAGE_VERSION = 'INVALID_MESSAGE_VERSION',

  /**
   * Sender key has expired based on time-based rotation policy.
   *
   * The default policy rotates sender keys every two weeks.
   * The caller should auto-rotate the sender key and redistribute to group members.
   */
  SENDER_KEY_EXPIRED = 'SENDER_KEY_EXPIRED',

  // ===== Identity & Trust Errors =====

  /**
   * Identity key is not trusted.
   *
   * User has not verified the identity or it has changed without confirmation.
   */
  UNTRUSTED_IDENTITY = 'UNTRUSTED_IDENTITY',

  /**
   * Identity key changed (possible MITM attack).
   *
   * Remote party's identity key differs from previously saved value.
   * Could be legitimate (reinstall) or an attack.
   */
  IDENTITY_KEY_CHANGED = 'IDENTITY_KEY_CHANGED',

  /**
   * Sender identity mismatch.
   *
   * The sender address in the message doesn't match the expected address.
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
   * Signed prekeys or Kyber prekeys have exceeded the maximum allowed age
   * (14 days by default). Message sending is blocked until rotation succeeds
   * to maintain forward-secrecy guarantees.
   *
   * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
   */
  PREKEY_ROTATION_REQUIRED = 'PREKEY_ROTATION_REQUIRED',

  /**
   * Invalid registration ID.
   *
   * Registration ID is 0 or doesn't match expected format.
   */
  INVALID_REGISTRATION_ID = 'INVALID_REGISTRATION_ID',

  /**
   * Registration ID changed (session reset detected).
   *
   * Remote party's registration ID changed, indicating app reinstall.
   * Old sessions should be archived.
   */
  REGISTRATION_ID_CHANGED = 'REGISTRATION_ID_CHANGED',

  // ===== Ratchet Errors =====

  /**
   * DH ratchet error.
   *
   * Diffie-Hellman key exchange failed or produced invalid output.
   */
  RATCHET_ERROR = 'RATCHET_ERROR',

  /**
   * Message counter overflow.
   *
   * Counter has reached MAX_SAFE_INTEGER - session must be rotated.
   * This is a safety check to prevent cryptographic issues from counter wrap-around.
   */
  COUNTER_OVERFLOW = 'COUNTER_OVERFLOW',

  /**
   * Invalid DH public key.
   *
   * DH public key is malformed or fails validation.
   */
  INVALID_DH_KEY = 'INVALID_DH_KEY',

  // ===== Storage Errors =====

  /** Key storage operation failed */
  KEY_STORAGE_ERROR = 'KEY_STORAGE_ERROR',

  /** Database operation failed */
  DATABASE_ERROR = 'DATABASE_ERROR',

  /**
   * Database is locked or unavailable.
   *
   * Encrypted database cannot be accessed (wrong password, corruption, etc.)
   */
  DATABASE_LOCKED = 'DATABASE_LOCKED',

  /**
   * The storage backend rejected a write because the origin's storage
   * quota is exhausted.
   *
   * The rejected write did not persist: storage adapters commit each
   * write in an atomic transaction, so quota exhaustion rolls the whole
   * transaction back instead of leaving a subset. The application should
   * free space or request more from the platform, then retry.
   */
  STORAGE_QUOTA_EXCEEDED = 'STORAGE_QUOTA_EXCEEDED',

  // ===== Initialization Errors =====

  /** Signal Protocol initialization failed */
  INITIALIZATION_FAILED = 'INITIALIZATION_FAILED',

  /** Identity key pair generation or loading failed */
  IDENTITY_KEY_ERROR = 'IDENTITY_KEY_ERROR',

  // ===== Protocol Strategy Errors =====

  /**
   * PQXDH (post-quantum key exchange) is required but partner lacks Kyber keys.
   *
   * Thrown when partner doesn't support the required PQXDH handshake.
   * Application can catch this to notify user or queue message for retry.
   */
  PQXDH_REQUIRED = 'PQXDH_REQUIRED',

  /**
   * PQXDH key exchange failed during handshake.
   *
   * The post-quantum key exchange encountered an error. The session is aborted
   * rather than downgraded to classical X3DH.
   */
  PQXDH_FAILED = 'PQXDH_FAILED',

  /**
   * Triple Ratchet is required but PQXDH was not used.
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
   * Attempted to use a message key that was already consumed.
   *
   * Indicates replay attack or duplicate message.
   *
   * Reserved: Reserved for future use when replay detection is implemented.
   */
  SPQR_KEY_ALREADY_USED = 'SPQR_KEY_ALREADY_USED',

  /**
   * SPQR message counter overflow.
   *
   * Counter has reached maximum value - epoch must be rotated.
   */
  SPQR_COUNTER_OVERFLOW = 'SPQR_COUNTER_OVERFLOW',

  /**
   * Invalid Kyber ciphertext in SPQR context.
   *
   * Ciphertext has wrong size or format for ML-KEM-1024.
   */
  SPQR_INVALID_CIPHERTEXT = 'SPQR_INVALID_CIPHERTEXT',

  /**
   * SPQR epoch regression detected.
   *
   * Received message claims an epoch earlier than current - possible replay.
   *
   * Reserved: Reserved for future use. Currently epoch regression is handled
   * via SPQR_EPOCH_OUT_OF_RANGE with oldestEpoch context.
   */
  SPQR_EPOCH_REGRESSION = 'SPQR_EPOCH_REGRESSION',

  /**
   * SPQR version negotiation failed.
   *
   * Peer's maximum supported version is below our minimum required version.
   * For example, peer only supports V0 but we require V1.
   */
  SPQR_VERSION_MISMATCH = 'SPQR_VERSION_MISMATCH',

  // ===== Cryptographic Errors =====

  /** Post-quantum (Kyber) operation failed */
  KYBER_ERROR = 'KYBER_ERROR',

  /** Key derivation function failed */
  KDF_ERROR = 'KDF_ERROR',

  /** HMAC verification failed (message tampering detected) */
  HMAC_VERIFICATION_FAILED = 'HMAC_VERIFICATION_FAILED',

  // ===== Sealed Sender Errors =====

  /**
   * Sealed sender authentication failed.
   *
   * The unidentified access key was rejected by the server. This may trigger
   * fallback to identified sender delivery.
   */
  SEALED_SENDER_AUTH_FAILED = 'SEALED_SENDER_AUTH_FAILED',

  // ===== Generic Errors =====

  /** Invalid operation or state */
  INVALID_STATE = 'INVALID_STATE',

  /** Unknown or unexpected error */
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
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
 * Error thrown when an identity key has changed.
 *
 * This could indicate:
 * - Legitimate: Device reinstall, new device, backup restoration
 * - Attack: Man-in-the-middle attack
 *
 * Requires prominent user warning and safety number verification.
 *
 * @example
 * ```typescript
 * throw new IdentityKeyChangedError(address, oldKey, newKey);
 * ```
 */
export class IdentityKeyChangedError extends EncryptionError {
  public readonly changedAddress: ProtocolAddress;
  public readonly oldIdentityKey: PublicKey;
  public readonly newIdentityKey: PublicKey;

  constructor(address: ProtocolAddress, oldIdentityKey: PublicKey, newIdentityKey: PublicKey) {
    super(
      `Identity key changed for ${address.userId}.${address.deviceId}`,
      EncryptionErrorCode.IDENTITY_KEY_CHANGED,
      { address, identityKey: newIdentityKey }
    );
    this.name = 'IdentityKeyChangedError';
    this.changedAddress = address;
    this.oldIdentityKey = oldIdentityKey;
    this.newIdentityKey = newIdentityKey;
  }
}

/**
 * Error thrown when multiple active sessions are detected (race condition).
 *
 * Occurs when both parties try to establish sessions simultaneously.
 * Requires session archiving and convergence using Sesame algorithm.
 *
 * @example
 * ```typescript
 * throw new SessionConflictError(address);
 * ```
 */
export class SessionConflictError extends EncryptionError {
  public readonly conflictAddress: ProtocolAddress;

  constructor(address: ProtocolAddress) {
    super(
      `Session conflict detected for ${address.userId}.${address.deviceId}`,
      EncryptionErrorCode.SESSION_CONFLICT,
      { address }
    );
    this.name = 'SessionConflictError';
    this.conflictAddress = address;
  }
}

/**
 * Error thrown when a duplicate message is detected (replay attack).
 *
 * This is a security-critical error indicating:
 * - Network replay (attacker re-sent a captured message)
 * - Client bug (accidentally decrypting same message twice)
 * - Storage corruption (message key index was corrupted)
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
  /** Message counter that was duplicated (if known) - matches the reference implementation's proto field name */
  public readonly counter?: number;
  /** Epoch (for Triple Ratchet) where duplicate was detected */
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
 * Error thrown when registration ID has changed (session reset).
 *
 * Indicates the remote party has reinstalled their app.
 * Old sessions should be archived and new session established.
 *
 * @example
 * ```typescript
 * throw new RegistrationIdChangedError(address, oldId, newId);
 * ```
 */
export class RegistrationIdChangedError extends EncryptionError {
  public readonly resetAddress: ProtocolAddress;
  public readonly oldRegistrationId: number;
  public readonly newRegistrationId: number;

  constructor(address: ProtocolAddress, oldRegistrationId: number, newRegistrationId: number) {
    super(
      `Registration ID changed for ${address.userId}.${address.deviceId} ` +
        `(${oldRegistrationId} → ${newRegistrationId})`,
      EncryptionErrorCode.REGISTRATION_ID_CHANGED,
      { address }
    );
    this.name = 'RegistrationIdChangedError';
    this.resetAddress = address;
    this.oldRegistrationId = oldRegistrationId;
    this.newRegistrationId = newRegistrationId;
  }
}

/**
 * Error thrown when sealed sender (anonymous delivery) authentication fails.
 *
 * The unidentified access key was rejected by the server, either because:
 * - The access key doesn't match the recipient's stored key
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
 * - `missing_keys`: Partner doesn't have Kyber prekeys (expected compatibility issue)
 * - `crypto_failure`: Kyber operation failed (decapsulation, signature, etc.)
 * - `protocol_mismatch`: Version or format incompatibility
 */
export type PQXDHFallbackType = 'missing_keys' | 'crypto_failure' | 'protocol_mismatch';

/**
 * Options for PQXDHRequiredError constructor.
 */
export interface PQXDHRequiredErrorOptions {
  /** Whether the operation can be retried (e.g., after partner updates keys) */
  retryable?: boolean;
  /** Suggested delay before retry in milliseconds */
  suggestedRetryDelay?: number;
  /** Category of fallback for analytics and handling */
  fallbackType?: PQXDHFallbackType;
  /** The underlying error that caused the failure */
  originalError?: Error;
}

/**
 * Error thrown when PQXDH is required but partner lacks Kyber keys.
 *
 * This is a recoverable error - applications can:
 * - Notify user that partner needs to update their app
 * - Queue the message for retry when partner uploads Kyber prekeys
 * - Fall back to classical encryption with user consent
 *
 * Recovery metadata:
 * - `retryable`: Whether the operation can be retried
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
  /** Whether the operation can be retried */
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
    this.retryable = opts.retryable ?? reason === 'no_kyber_prekey'; // Missing keys can be retried after partner updates
    this.suggestedRetryDelay = opts.suggestedRetryDelay ?? (this.retryable ? 30000 : undefined); // 30s default for retryable
  }
}

/**
 * Error thrown when the storage backend rejects a write because the
 * origin's storage quota is exhausted.
 *
 * The rejected write did not persist: storage adapters commit each write
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
 * Type guard to check if an error is an IdentityKeyChangedError.
 *
 * @param error - Error to check
 * @returns true if error is IdentityKeyChangedError
 */
export function isIdentityKeyChangedError(error: unknown): error is IdentityKeyChangedError {
  return error instanceof IdentityKeyChangedError;
}

/**
 * Type guard to check if an error is a SessionConflictError.
 *
 * @param error - Error to check
 * @returns true if error is SessionConflictError
 */
export function isSessionConflictError(error: unknown): error is SessionConflictError {
  return error instanceof SessionConflictError;
}

/**
 * Type guard to check if an error is a RegistrationIdChangedError.
 *
 * @param error - Error to check
 * @returns true if error is RegistrationIdChangedError
 */
export function isRegistrationIdChangedError(error: unknown): error is RegistrationIdChangedError {
  return error instanceof RegistrationIdChangedError;
}

// ============================================================================
// Tiered Error Classes (Layer-Aligned)
// ============================================================================

/**
 * Error codes for cryptographic layer (Layer 1) errors.
 *
 * These errors occur in low-level cryptographic operations.
 */
export enum CryptoErrorCode {
  /** Random number generation failed */
  RNG_FAILURE = 'CRYPTO_RNG_FAILURE',
  /** ECDH key agreement failed */
  ECDH_FAILURE = 'CRYPTO_ECDH_FAILURE',
  /** Kyber (ML-KEM) operation failed */
  KYBER_FAILURE = 'CRYPTO_KYBER_FAILURE',
  /** Key derivation function failed */
  KDF_FAILURE = 'CRYPTO_KDF_FAILURE',
  /** AES encryption/decryption failed */
  AES_FAILURE = 'CRYPTO_AES_FAILURE',
  /** HMAC computation or verification failed */
  HMAC_FAILURE = 'CRYPTO_HMAC_FAILURE',
  /** Digital signature failed */
  SIGNATURE_FAILURE = 'CRYPTO_SIGNATURE_FAILURE',
  /** Hash computation failed */
  HASH_FAILURE = 'CRYPTO_HASH_FAILURE',
  /** Invalid key format or length */
  INVALID_KEY = 'CRYPTO_INVALID_KEY',
  /** Invalid ciphertext format */
  INVALID_CIPHERTEXT = 'CRYPTO_INVALID_CIPHERTEXT',
}

/**
 * Cryptographic layer error (Layer 1).
 *
 * Thrown when low-level cryptographic operations fail.
 * These errors are typically unrecoverable and indicate
 * fundamental issues with crypto primitives.
 *
 * @example
 * ```typescript
 * throw new CryptoError(
 *   'ECDH key agreement produced invalid output',
 *   CryptoErrorCode.ECDH_FAILURE,
 *   { operation: 'computeSharedSecret' }
 * );
 * ```
 */
export class CryptoError extends EncryptionError {
  public readonly cryptoCode: CryptoErrorCode;

  constructor(message: string, code: CryptoErrorCode, context?: EncryptionErrorContext) {
    // Map to base EncryptionErrorCode for compatibility
    const baseCode = mapCryptoToEncryptionCode(code);
    super(message, baseCode, context);
    this.name = 'CryptoError';
    this.cryptoCode = code;
  }
}

/**
 * Error codes for session layer (Layer 5) errors.
 *
 * These errors occur during session operations.
 */
export enum SessionErrorCode {
  /** Session not found */
  NOT_FOUND = 'SESSION_NOT_FOUND',
  /** Session is corrupted or invalid */
  CORRUPTED = 'SESSION_CORRUPTED',
  /** Session has expired */
  EXPIRED = 'SESSION_EXPIRED',
  /** Session conflict (race condition) */
  CONFLICT = 'SESSION_CONFLICT',
  /** Invalid session state for operation */
  INVALID_STATE = 'SESSION_INVALID_STATE',
  /** Session ratchet step failed */
  RATCHET_FAILED = 'SESSION_RATCHET_FAILED',
  /** Too many skipped messages */
  TOO_MANY_SKIPPED = 'SESSION_TOO_MANY_SKIPPED',
  /** Message key not found (message too old) */
  MESSAGE_KEY_NOT_FOUND = 'SESSION_MESSAGE_KEY_NOT_FOUND',
  /** Session establishment failed */
  ESTABLISHMENT_FAILED = 'SESSION_ESTABLISHMENT_FAILED',
}

/**
 * Session layer error (Layer 5).
 *
 * Thrown when session operations fail. Includes session ID
 * for debugging and potentially recovery.
 *
 * @example
 * ```typescript
 * throw new SessionError(
 *   'Session not found for decryption',
 *   SessionErrorCode.NOT_FOUND,
 *   'session-123',
 *   { operation: 'decrypt' }
 * );
 * ```
 */
export class SessionError extends EncryptionError {
  public readonly sessionCode: SessionErrorCode;
  public readonly sessionId?: string;

  constructor(
    message: string,
    code: SessionErrorCode,
    sessionId?: string,
    context?: EncryptionErrorContext
  ) {
    // Map to base EncryptionErrorCode for compatibility
    const baseCode = mapSessionToEncryptionCode(code);
    super(message, baseCode, context);
    this.name = 'SessionError';
    this.sessionCode = code;
    this.sessionId = sessionId;
  }
}

/**
 * Error codes for protocol layer (Layer 6) errors.
 *
 * These errors occur at the protocol level (Sesame, message routing).
 */
export enum ProtocolErrorCode {
  /** Invalid message format */
  INVALID_MESSAGE = 'PROTOCOL_INVALID_MESSAGE',
  /** Invalid prekey bundle */
  INVALID_BUNDLE = 'PROTOCOL_INVALID_BUNDLE',
  /** Protocol version mismatch */
  VERSION_MISMATCH = 'PROTOCOL_VERSION_MISMATCH',
  /** Device not found in device list */
  DEVICE_NOT_FOUND = 'PROTOCOL_DEVICE_NOT_FOUND',
  /** Stale device list */
  STALE_DEVICE_LIST = 'PROTOCOL_STALE_DEVICE_LIST',
  /** Retry request required */
  RETRY_REQUIRED = 'PROTOCOL_RETRY_REQUIRED',
  /** Sender key distribution failed */
  SENDER_KEY_FAILED = 'PROTOCOL_SENDER_KEY_FAILED',
}

/**
 * Protocol layer error (Layer 6).
 *
 * Thrown for protocol-level issues like message format errors,
 * version mismatches, or multi-device coordination failures.
 *
 * @example
 * ```typescript
 * throw new ProtocolError(
 *   'Device list is stale, retry required',
 *   ProtocolErrorCode.STALE_DEVICE_LIST,
 *   { operation: 'sendGroupMessage', context: { groupId } }
 * );
 * ```
 */
export class ProtocolError extends EncryptionError {
  public readonly protocolCode: ProtocolErrorCode;
  public readonly protocolContext?: object;

  constructor(
    message: string,
    code: ProtocolErrorCode,
    context?: EncryptionErrorContext & { protocolContext?: object }
  ) {
    // Map to base EncryptionErrorCode for compatibility
    const baseCode = mapProtocolToEncryptionCode(code);
    super(message, baseCode, context);
    this.name = 'ProtocolError';
    this.protocolCode = code;
    this.protocolContext = context?.protocolContext;
  }
}

/**
 * Error codes for client-facing errors.
 *
 * These errors should be displayed to users (with appropriate messaging).
 */
export enum ClientErrorCode {
  /** Network error during key exchange */
  NETWORK_ERROR = 'CLIENT_NETWORK_ERROR',
  /** User identity verification required */
  VERIFICATION_REQUIRED = 'CLIENT_VERIFICATION_REQUIRED',
  /** Recipient not found */
  RECIPIENT_NOT_FOUND = 'CLIENT_RECIPIENT_NOT_FOUND',
  /** Message delivery failed */
  DELIVERY_FAILED = 'CLIENT_DELIVERY_FAILED',
  /** Encryption unavailable (keys not initialized) */
  ENCRYPTION_UNAVAILABLE = 'CLIENT_ENCRYPTION_UNAVAILABLE',
  /** Session needs reset */
  SESSION_RESET_NEEDED = 'CLIENT_SESSION_RESET_NEEDED',
}

/**
 * Client-facing error.
 *
 * These errors are intended to be shown to users with
 * appropriate messaging. Includes optional user-facing
 * message that can be displayed directly in UI.
 *
 * @example
 * ```typescript
 * throw new ClientError(
 *   'Failed to send encrypted message',
 *   ClientErrorCode.DELIVERY_FAILED,
 *   'Message could not be delivered. Please try again.',
 *   { operation: 'sendMessage' }
 * );
 * ```
 */
export class ClientError extends EncryptionError {
  public readonly clientCode: ClientErrorCode;
  public readonly userFacingMessage?: string;

  constructor(
    message: string,
    code: ClientErrorCode,
    userFacingMessage?: string,
    context?: EncryptionErrorContext
  ) {
    // Map to base EncryptionErrorCode for compatibility
    const baseCode = mapClientToEncryptionCode(code);
    super(message, baseCode, context);
    this.name = 'ClientError';
    this.clientCode = code;
    this.userFacingMessage = userFacingMessage;
  }
}

// ============================================================================
// Error Code Mapping (Record-based with compile-time exhaustiveness)
// ============================================================================

/**
 * Map CryptoErrorCode to EncryptionErrorCode.
 *
 * Using Record type ensures compile-time exhaustiveness - TypeScript will
 * error if we add a new CryptoErrorCode without adding a mapping.
 */
const cryptoToEncryptionCodeMap: Record<CryptoErrorCode, EncryptionErrorCode> = {
  [CryptoErrorCode.RNG_FAILURE]: EncryptionErrorCode.ENCRYPTION_FAILED,
  [CryptoErrorCode.ECDH_FAILURE]: EncryptionErrorCode.ENCRYPTION_FAILED,
  [CryptoErrorCode.KYBER_FAILURE]: EncryptionErrorCode.KYBER_ERROR,
  [CryptoErrorCode.KDF_FAILURE]: EncryptionErrorCode.KDF_ERROR,
  [CryptoErrorCode.AES_FAILURE]: EncryptionErrorCode.ENCRYPTION_FAILED,
  [CryptoErrorCode.HMAC_FAILURE]: EncryptionErrorCode.HMAC_VERIFICATION_FAILED,
  [CryptoErrorCode.SIGNATURE_FAILURE]: EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED,
  [CryptoErrorCode.HASH_FAILURE]: EncryptionErrorCode.ENCRYPTION_FAILED,
  [CryptoErrorCode.INVALID_KEY]: EncryptionErrorCode.INVALID_DH_KEY,
  [CryptoErrorCode.INVALID_CIPHERTEXT]: EncryptionErrorCode.INVALID_CIPHERTEXT,
};

function mapCryptoToEncryptionCode(code: CryptoErrorCode): EncryptionErrorCode {
  return cryptoToEncryptionCodeMap[code];
}

/**
 * Map SessionErrorCode to EncryptionErrorCode.
 */
const sessionToEncryptionCodeMap: Record<SessionErrorCode, EncryptionErrorCode> = {
  [SessionErrorCode.NOT_FOUND]: EncryptionErrorCode.SESSION_NOT_FOUND,
  [SessionErrorCode.CORRUPTED]: EncryptionErrorCode.SESSION_CORRUPTED,
  [SessionErrorCode.EXPIRED]: EncryptionErrorCode.SESSION_NOT_FOUND, // Treat expired as not found
  [SessionErrorCode.CONFLICT]: EncryptionErrorCode.SESSION_CONFLICT,
  [SessionErrorCode.INVALID_STATE]: EncryptionErrorCode.INVALID_STATE,
  [SessionErrorCode.RATCHET_FAILED]: EncryptionErrorCode.RATCHET_ERROR,
  [SessionErrorCode.TOO_MANY_SKIPPED]: EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES,
  [SessionErrorCode.MESSAGE_KEY_NOT_FOUND]: EncryptionErrorCode.MESSAGE_TOO_OLD,
  [SessionErrorCode.ESTABLISHMENT_FAILED]: EncryptionErrorCode.SESSION_NOT_FOUND,
};

function mapSessionToEncryptionCode(code: SessionErrorCode): EncryptionErrorCode {
  return sessionToEncryptionCodeMap[code];
}

/**
 * Map ProtocolErrorCode to EncryptionErrorCode.
 */
const protocolToEncryptionCodeMap: Record<ProtocolErrorCode, EncryptionErrorCode> = {
  [ProtocolErrorCode.INVALID_MESSAGE]: EncryptionErrorCode.INVALID_CIPHERTEXT,
  [ProtocolErrorCode.INVALID_BUNDLE]: EncryptionErrorCode.INVALID_PREKEY_BUNDLE,
  [ProtocolErrorCode.VERSION_MISMATCH]: EncryptionErrorCode.INVALID_MESSAGE_VERSION,
  [ProtocolErrorCode.DEVICE_NOT_FOUND]: EncryptionErrorCode.SESSION_NOT_FOUND,
  [ProtocolErrorCode.STALE_DEVICE_LIST]: EncryptionErrorCode.INVALID_STATE,
  [ProtocolErrorCode.RETRY_REQUIRED]: EncryptionErrorCode.INVALID_STATE,
  [ProtocolErrorCode.SENDER_KEY_FAILED]: EncryptionErrorCode.ENCRYPTION_FAILED,
};

function mapProtocolToEncryptionCode(code: ProtocolErrorCode): EncryptionErrorCode {
  return protocolToEncryptionCodeMap[code];
}

/**
 * Map ClientErrorCode to EncryptionErrorCode.
 */
const clientToEncryptionCodeMap: Record<ClientErrorCode, EncryptionErrorCode> = {
  [ClientErrorCode.NETWORK_ERROR]: EncryptionErrorCode.UNKNOWN_ERROR,
  [ClientErrorCode.VERIFICATION_REQUIRED]: EncryptionErrorCode.UNTRUSTED_IDENTITY,
  [ClientErrorCode.RECIPIENT_NOT_FOUND]: EncryptionErrorCode.SESSION_NOT_FOUND,
  [ClientErrorCode.DELIVERY_FAILED]: EncryptionErrorCode.ENCRYPTION_FAILED,
  [ClientErrorCode.ENCRYPTION_UNAVAILABLE]: EncryptionErrorCode.INITIALIZATION_FAILED,
  [ClientErrorCode.SESSION_RESET_NEEDED]: EncryptionErrorCode.SESSION_NOT_FOUND,
};

function mapClientToEncryptionCode(code: ClientErrorCode): EncryptionErrorCode {
  return clientToEncryptionCodeMap[code];
}

// ============================================================================
// Type Guards for Tiered Errors
// ============================================================================

/**
 * Type guard to check if an error is a CryptoError.
 */
export function isCryptoError(error: unknown): error is CryptoError {
  return error instanceof CryptoError;
}

/**
 * Type guard to check if an error is a SessionError.
 */
export function isSessionError(error: unknown): error is SessionError {
  return error instanceof SessionError;
}

/**
 * Type guard to check if an error is a ProtocolError.
 */
export function isProtocolError(error: unknown): error is ProtocolError {
  return error instanceof ProtocolError;
}

/**
 * Type guard to check if an error is a ClientError.
 */
export function isClientError(error: unknown): error is ClientError {
  return error instanceof ClientError;
}

/**
 * Type guard to check if an error is any Signal Protocol error.
 */
export function isEncryptionError(error: unknown): error is EncryptionError {
  return error instanceof EncryptionError;
}
