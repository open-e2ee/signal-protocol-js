/**
 * Session State Operations
 *
 * Handles session state management including:
 * - Type guard for validated sessions (SessionState → DoubleRatchetState compatible)
 * - DH ratchet steps (purely classical EC)
 * - Skipped key storage and cleanup
 *
 * Design: Uses TypeScript structural typing to pass SessionState directly to
 * double-ratchet functions when validated (DHs and DHr are non-null).
 * This eliminates adapter overhead while preserving type safety.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../logger';
import type { SessionState } from '../../types';
import { EncryptionError, EncryptionErrorCode } from '../../types';
import { DEFAULT_RATCHET_CONFIG } from '../protocol/double-ratchet';
import type { DoubleRatchetConfig } from '../protocol/double-ratchet';
import type { DoubleRatchetState } from '../protocol/double-ratchet';
import {
  performDHRatchetStep as moduleDHRatchetStep,
  storeSkippedKeys as moduleStoreSkippedKeys,
  cleanupExpiredKeys as moduleCleanupExpiredKeys,
} from '../protocol/double-ratchet';
// ============================================================================
// Type Guard for Validated Sessions
// ============================================================================

/**
 * SessionState with non-null DHs and DHr, structurally compatible with DoubleRatchetState.
 *
 * TypeScript structural typing: When SessionState has non-null DHs/DHr,
 * it satisfies the DoubleRatchetState interface because:
 * - SessionState.DHs: { publicKey: string; privateKey: string } matches RatchetKeyPair
 * - SessionState.DHr: string matches Base64 (which is string)
 * - All other ratchet fields (RK, CKs, CKr, etc.) have identical types
 *
 * This allows passing validated SessionState directly to double-ratchet functions.
 */
export {};
export type ValidatedSessionState = SessionState & {
  DHs: NonNullable<SessionState['DHs']>;
  DHr: NonNullable<SessionState['DHr']>;
  CKs: NonNullable<SessionState['CKs']>;
  // Note: CKr intentionally excluded — initiator sessions have CKr=undefined
  // until first message received. CKr is validated at point of use in
  // deriveReceivingKey() via length check (chains.ts:101-107).
};

/**
 * Type guard that validates and narrows SessionState to ValidatedSessionState.
 *
 * After this check passes, the session can be passed directly to
 * DoubleRatchetState-accepting functions via TypeScript's structural typing.
 *
 * @param session SessionState to validate
 * @returns true if session has non-null DHs and DHr
 */
export function isValidatedSession(session: SessionState): session is ValidatedSessionState {
  // Use loose equality to catch both null and undefined (lazy init uses undefined for DHr)
  return session.DHs != null && session.DHr != null;
}

/**
 * Assert that session is validated for encryption, throwing descriptive error if not.
 *
 * For encryption, the session must be fully initialized:
 * - DHs, DHr must be set (DH ratchet keys)
 * - CKs must be set (sending chain key for deriving message keys)
 *
 * For lazy-initialized responder sessions, encrypt should fail until
 * the first message has been received and decrypted (which triggers
 * DHRatchet and sets all required keys).
 *
 * @param session SessionState to validate
 * @param operation Operation name for error message
 * @throws EncryptionError if session is not validated
 */
export function assertValidatedSession(
  session: SessionState,
  operation: string
): asserts session is ValidatedSessionState {
  if (!session.DHs) {
    throw new EncryptionError(
      `Cannot ${operation}: DHs is null (session not initialized)`,
      EncryptionErrorCode.SESSION_CORRUPTED
    );
  }
  if (!session.DHr) {
    throw new EncryptionError(
      `Cannot ${operation}: DHr is undefined (lazy init not complete - receive a message first)`,
      EncryptionErrorCode.SESSION_CORRUPTED
    );
  }
  if (!session.CKs) {
    throw new EncryptionError(
      `Cannot ${operation}: CKs is undefined (lazy init not complete - receive a message first)`,
      EncryptionErrorCode.SESSION_CORRUPTED
    );
  }
}

// ============================================================================
// DH Ratchet
// ============================================================================

/**
 * Perform DH ratchet step (purely classical EC).
 *
 * The DH ratchet has no interaction with PQ/SPQR state. All post-quantum work
 * happens in `spqrSend()` and `spqrRecv()`.
 *
 * Design: For lazy initialization (responder's first message), DHr may be
 * undefined. The DHRatchet step will set DHr from the received message.
 * For normal ratchets, both DHs and DHr must be valid.
 *
 * Per Signal Protocol Section 3.3 -
 * - RatchetInitBob sets DHr = None initially
 * - DHRatchet step sets DHr = header.dh when processing first message
 *
 * TypeScript structural typing allows ValidatedSessionState to satisfy
 * DoubleRatchetState interface - mutations happen directly on session.
 */
export async function performDHRatchetStep(
  session: SessionState,
  receivedDHPublicKey: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<void> {
  // For lazy initialization (responder's first message), DHr is undefined
  // but DHs must be valid (set to signed prekey during session establishment)
  const isLazyInit = session.DHr === undefined;

  if (!session.DHs) {
    throw new EncryptionError(
      'Cannot perform DH ratchet: DHs is null (session not initialized)',
      EncryptionErrorCode.SESSION_CORRUPTED
    );
  }

  if (isLazyInit) {
    logger.debug('Lazy init DHRatchet: Setting DHr from received message', {
      category: 'E2EE',
      data: {
        operation: 'dh-ratchet-lazy-init',
        receivedDHrPreview: receivedDHPublicKey.substring(0, 20),
      },
    });
  }

  // For lazy init, we need to create a temporary state with DHr set
  // so it satisfies DoubleRatchetState interface
  // The module will update DHr anyway, but we need valid types
  const stateForRatchet = session as unknown as DoubleRatchetState;

  // Pass session directly - mutations happen in place
  await moduleDHRatchetStep(stateForRatchet, receivedDHPublicKey, logger);

  // Verify DHRatchet set all required session keys
  // This catches edge cases where mutation fails silently due to the type cast
  if (!session.DHr || !session.CKs || !session.CKr) {
    throw new EncryptionError(
      'DHRatchet failed to initialize session state',
      EncryptionErrorCode.SESSION_CORRUPTED,
      {
        operation: 'performDHRatchetStep',
        DHrSet: !!session.DHr,
        CKsSet: !!session.CKs,
        CKrSet: !!session.CKr,
      }
    );
  }
}

// ============================================================================
// Skipped Key Storage
// ============================================================================

/**
 * Store skipped message keys when advancing receiving chain
 *
 * Design: Validates session then passes directly to double-ratchet module.
 * Mutations happen in place on the session object.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#out-of-order-messages
 */
export async function storeSkippedMessageKeys(
  session: SessionState,
  untilCounter: number,
  config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<void> {
  // Validate session - this narrows type to ValidatedSessionState
  assertValidatedSession(session, 'store skipped message keys');

  try {
    // Pass session directly - mutations happen in place
    await moduleStoreSkippedKeys(
      session as DoubleRatchetState,
      untilCounter,
      {
        maxSkippedMessages: config.maxSkippedMessages,
        maxMessageKeysStored: config.maxMessageKeysStored,
        maxMessageKeyAge: config.maxMessageKeyAge,
        kyberRefreshInterval: config.kyberRefreshInterval,
      },
      logger
    );
  } catch (error) {
    if (error instanceof Error && error.message.includes('Too many skipped messages')) {
      throw new EncryptionError(error.message, EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES);
    }
    throw error;
  }
}

// ============================================================================
// Cleanup
// ============================================================================

/**
 * Clean up expired message keys from MKSKIPPED dictionary
 *
 * Design: For cleanup, we only need a validated session if we're going to
 * run cleanup. If session is not validated, we silently skip (nothing to clean).
 *
 * Signal Protocol Section 8.4
 */
export function cleanupExpiredMessageKeys(
  session: SessionState,
  config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): void {
  // Skip cleanup if session not validated (nothing to clean)
  if (!isValidatedSession(session)) {
    return;
  }

  // Pass session directly - mutations happen in place on MKSKIPPED
  moduleCleanupExpiredKeys(
    session as DoubleRatchetState,
    {
      maxSkippedMessages: config.maxSkippedMessages,
      maxMessageKeysStored: config.maxMessageKeysStored,
      maxMessageKeyAge: config.maxMessageKeyAge,
      kyberRefreshInterval: config.kyberRefreshInterval,
    },
    logger
  );

  // Clean up expired processedChains entries (matches MKSKIPPED 7-day policy)
  cleanupExpiredProcessedChains(session);
}

/**
 * Remove processedChains entries older than 7 days.
 *
 * The processedChains dictionary grows without bound as each DH ratchet adds
 * an entry. This cleanup matches the MKSKIPPED 7-day expiration policy from
 * Signal Protocol Section 8.4.
 *
 * @param session - Session state containing processedChains
 */
function cleanupExpiredProcessedChains(session: SessionState): void {
  if (!session.processedChains) return;
  const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  const now = Date.now();
  for (const key of Object.keys(session.processedChains)) {
    if (now - session.processedChains[key].timestamp > maxAge) {
      delete session.processedChains[key];
    }
  }
}
