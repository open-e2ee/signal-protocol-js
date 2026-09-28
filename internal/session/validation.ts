/**
 * Session Validation Utilities
 *
 * Shared validation functions for session state used by encryption and decryption.
 *
 * @internal This module is INTERNAL. Use SignalProtocolClient for public API.
 */

import { EncryptionError, EncryptionErrorCode } from '../../types/errors';
import type { Base64 } from '../../types/utils';
import type { SessionState } from '../../types';
import { defaultSignalProtocolLogger, type Logger } from '../../logger';
import {
  compositeIdentitiesEqual,
  createCompositeIdentityV1,
  encodeCompositeIdentityV1,
} from '../../keys/identity';

export {};

/**
 * Validate session key ownership to detect corrupted sessions.
 *
 * Detects the "swapped keys" bug where a responder session has:
 * - DHs = sender's ephemeral key (WRONG - should be our signed prekey)
 * - DHr = our own signed prekey (WRONG - should be sender's DH key)
 *
 * For a responder session (isInitiator = false):
 * - DHs MUST be our own signed prekey
 * - DHr should NOT equal our own signed prekey
 *
 * For an initiator session (isInitiator = true):
 * - DHs MUST be our ephemeral key (different from signed prekey)
 * - DHr MUST be recipient's signed prekey
 *
 * @param session Session state to validate
 * @param mySignedPreKeyPublic Our current signed prekey's public key (base64)
 * @throws EncryptionError with SESSION_CORRUPTED if keys are swapped
 */
export function validateSessionKeyOwnership(
  session: SessionState,
  mySignedPreKeyPublic: Base64 | undefined,
  logger: Required<Logger> = defaultSignalProtocolLogger
): void {
  // Skip validation if we do not have a signed prekey to compare
  if (!mySignedPreKeyPublic) {
    logger.warn('Cannot validate session key ownership: no signed prekey available', {
      category: 'E2EE',
      data: { isInitiator: session.isInitiator },
    });
    return;
  }

  if (!session.isInitiator) {
    // RESPONDER session validation
    // DHs should be our signed prekey
    // DHr should NOT be our signed prekey (would indicate swapped keys)

    if (session.DHr !== undefined && session.DHr === mySignedPreKeyPublic) {
      // BUG DETECTED: DHr equals our own signed prekey
      // This means keys are swapped - we are trying to compute DH with ourselves
      logger.error('Session corrupted: DHr equals our own signed prekey (keys swapped)', {
        category: 'SECURITY',
        data: {
          isInitiator: session.isInitiator,
          DHrPrefix: session.DHr.substring(0, 20),
          mySignedPreKeyPrefix: mySignedPreKeyPublic.substring(0, 20),
        },
      });

      throw new EncryptionError(
        'Session corrupted: DHr equals our own signed prekey. ' +
          'This indicates the session keys are swapped and decryption will fail.',
        EncryptionErrorCode.SESSION_CORRUPTED,
        {
          isInitiator: session.isInitiator,
          reason: 'swapped_keys',
        }
      );
    }

    // Optionally validate DHs equals our signed prekey
    if (session.DHs?.publicKey && session.DHs.publicKey !== mySignedPreKeyPublic) {
      // This might not be an error - DHs gets updated after DHRatchet
      // Only log as warning for diagnostics
      logger.debug('Responder DHs differs from current signed prekey (may be post-ratchet)', {
        category: 'E2EE',
        data: {
          DHsPrefix: session.DHs.publicKey.substring(0, 20),
          signedPreKeyPrefix: mySignedPreKeyPublic.substring(0, 20),
        },
      });
    }
  } else {
    // INITIATOR session validation
    // DHs should NOT be our signed prekey (it should be our ephemeral)
    // DHr should be recipient's signed prekey

    if (session.DHs?.publicKey === mySignedPreKeyPublic) {
      // BUG DETECTED: Initiator DHs equals our signed prekey
      // This is wrong - initiator should use ephemeral key, not signed prekey
      logger.error('Session corrupted: Initiator DHs equals our signed prekey', {
        category: 'SECURITY',
        data: {
          isInitiator: session.isInitiator,
          DHsPrefix: session.DHs.publicKey.substring(0, 20),
        },
      });

      throw new EncryptionError(
        'Session corrupted: Initiator DHs should be ephemeral key, not signed prekey.',
        EncryptionErrorCode.SESSION_CORRUPTED,
        {
          isInitiator: session.isInitiator,
          reason: 'initiator_wrong_dhs',
        }
      );
    }
  }
}

/**
 * Validate session state integrity for critical fields.
 *
 * Detects corruption in session state that would cause runtime errors:
 * - receiverChains must be an array (not undefined/null)
 * - Essential fields must be present
 *
 * @param session Session state to validate
 * @throws EncryptionError with SESSION_CORRUPTED if state is corrupted
 */
export function validateSessionStateIntegrity(
  session: SessionState,
  logger: Required<Logger> = defaultSignalProtocolLogger
): void {
  try {
    encodeCompositeIdentityV1(session.localIdentity);
    encodeCompositeIdentityV1(session.remoteIdentity);
    const identityFromPrivateState = createCompositeIdentityV1(session.identityKeyPair);
    if (!compositeIdentitiesEqual(identityFromPrivateState, session.localIdentity)) {
      throw new Error('cached local identity does not match the session identity keypair');
    }
  } catch (error) {
    throw new EncryptionError(
      'Session corrupted: composite identity binding is missing or inconsistent.',
      EncryptionErrorCode.SESSION_CORRUPTED,
      {
        reason: 'composite_identity_mismatch',
        originalError: error as Error,
      }
    );
  }

  // receiverChains must be an array, not undefined/null
  // Accessing undefined.prop causes TypeError which gets wrapped as DECRYPTION_FAILED
  if (session.receiverChains === undefined || session.receiverChains === null) {
    logger.error('Session corrupted: receiverChains is undefined or null', {
      category: 'SECURITY',
      data: {
        isInitiator: session.isInitiator,
        hasReceiverChains: session.receiverChains !== undefined,
        reason: 'receiverChains_undefined',
      },
    });

    throw new EncryptionError(
      'Session corrupted: receiverChains array is missing. ' +
        'This indicates session state corruption that would cause runtime errors.',
      EncryptionErrorCode.SESSION_CORRUPTED,
      {
        isInitiator: session.isInitiator,
        reason: 'receiverChains_undefined',
      }
    );
  }

  // receiverChains must be an array (not a primitive or object)
  if (!Array.isArray(session.receiverChains)) {
    logger.error('Session corrupted: receiverChains is not an array', {
      category: 'SECURITY',
      data: {
        isInitiator: session.isInitiator,
        receiverChainsType: typeof session.receiverChains,
        reason: 'receiverChains_invalid_type',
      },
    });

    throw new EncryptionError(
      `Session corrupted: receiverChains is ${typeof session.receiverChains}, expected array. ` +
        'This indicates session state corruption.',
      EncryptionErrorCode.SESSION_CORRUPTED,
      {
        isInitiator: session.isInitiator,
        reason: 'receiverChains_invalid_type',
      }
    );
  }

  // DHr must not be an empty string if defined.
  // Empty string DHr passes truthy checks but creates invalid keyIds for MKSKIPPED
  // (e.g., ":0" instead of "validKey:0"), corrupting skipped message key lookups.
  // An undefined/null DHr is valid (lazy init for responder's first message).
  if (session.DHr !== undefined && session.DHr !== null && session.DHr === '') {
    logger.error('Session corrupted: DHr is empty string', {
      category: 'SECURITY',
      data: {
        isInitiator: session.isInitiator,
        reason: 'empty_dhr',
      },
    });

    throw new EncryptionError(
      'Session corrupted: DHr is empty string. ' +
        'This creates invalid keyIds for skipped message key lookups.',
      EncryptionErrorCode.SESSION_CORRUPTED,
      {
        isInitiator: session.isInitiator,
        reason: 'empty_dhr',
      }
    );
  }
}

// ============================================================================
// Self-session detection (Note to Self)
// ============================================================================

/**
 * Detect if a session is a self-session ("Note to Self").
 *
 * Self-sessions occur when local identity key equals remote identity key.
 * These sessions require special handling:
 * - Unlimited MAX_SKIP (synchronization can involve large gaps)
 * - No identity trust warnings (always trusted)
 * @param session Session state to check
 * @returns true if this is a self-session
 */
export function isSelfSession(session: SessionState): boolean {
  return compositeIdentitiesEqual(session.localIdentity, session.remoteIdentity);
}

/**
 * Get maxSkippedMessages for a session.
 *
 * Self-sessions use a 100,000-message limit. This accommodates large
 * Note-to-Self synchronization gaps while keeping forged counters bounded.
 *
 * @param session Session state
 * @param defaultMaxSkip Default MAX_SKIP for non-self sessions
 * @returns maxSkippedMessages limit to use
 */
export function getMaxSkipForSession(session: SessionState, defaultMaxSkip: number): number {
  if (isSelfSession(session)) {
    // Self-sessions can have larger gaps from multi-device sync, but still need
    // a bound to prevent DoS from forged messages with huge counter values.
    // 100,000 is generous enough for real sync scenarios.
    return 100_000;
  }
  return defaultMaxSkip;
}
