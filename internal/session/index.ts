/**
 * Session Module - Session State Factory, Session Builder, and Session Cipher
 *
 * @internal This module is INTERNAL. Use SignalProtocolClient for public encryption API.
 *
 * @layer 3 - Domain/Session
 * @depends Layer 4 (key-exchange, ratchet), Layer 5 (keys), Layer 6 (crypto)
 *
 * Provides:
 * - Factory functions for creating Signal Protocol session states
 * - SessionBuilder class for X3DH/PQXDH key agreement and session establishment
 * - SessionCipher class for encrypt/decrypt operations using Double Ratchet
 * - Branded key types for type-safe session key handling
 *
 * @example Factory Functions (low-level, internal use)
 * ```typescript
 * import { createInitiatorSession, createResponderSession } from './';
 *
 * const aliceSession = createInitiatorSession({ ... });
 * const bobSession = createResponderSession({ ... });
 * ```
 *
 * @example SessionBuilder (high-level session establishment, internal use)
 * ```typescript
 * import { SessionBuilder } from './';
 *
 * // As initiator (Alice)
 * const result = await SessionBuilder.buildInitiatorSession({
 *   sessionId,
 *   localAddress: aliceId,
 *   remoteAddress: bobId,
 *   identityKeyPair: aliceIdentity,
 *   preKeyBundle: bobPreKeyBundle,
 * });
 *
 * // As responder (Bob)
 * const result = await SessionBuilder.buildResponderSession({
 *   sessionId,
 *   remoteAddress: aliceId,
 *   identityKeyPair: bobIdentity,
 *   prekeyMessage: alicePreKeyMessage,
 *   ecSignedPreKey: bobSignedPreKey,
 *   ecOneTimePreKey: bobOneTimePreKey,
 *   kemLastResortPreKey: bobKyberPreKey,
 * });
 * ```
 *
 * @example SessionCipher (encrypt/decrypt, internal use)
 * ```typescript
 * import { SessionCipher } from './';
 *
 * const cipher = new SessionCipher(keyStorage, establishSession, lock);
 *
 * // Encrypt
 * const ciphertext = await cipher.encrypt(sessionId, 'Hello!');
 *
 * // Decrypt
 * const plaintext = await cipher.decrypt(sessionId, ciphertext);
 * ```
 */

// ============================================================================
// Branded Key Types for Type Safety
// ============================================================================
export {};
export type {
  RootKey,
  ChainKey,
  MessageKey,
  KDFRootKeyOutput,
  KDFChainKeyOutput,
  ExpandedMessageKey,
  SendingChainState,
  ReceivingChainState,
  SkippedMessageKeyEntry,
  SkippedMessageKeyDict,
} from './keys';

export {
  asRootKey,
  asChainKey,
  asMessageKey,
  SESSION_KEY_BYTES,
  MAX_FORWARD_JUMPS,
  MESSAGE_KEY_EXPIRATION_MS,
} from './keys';

// ============================================================================
// Session State Machine Types
// ============================================================================
export type {
  SessionPhase,
  UninitializedSession,
  PendingSession,
  ActiveSession,
  RekeyingSession,
  ExpiredSession,
  TypedSessionState,
} from './state';

export {
  isUninitialized,
  isPending,
  isActive,
  isRekeying,
  isExpired,
  canEncrypt,
  canDecrypt,
  isEstablished,
  needsInitialization,
  awaitingFirstMessage,
  isValidTransition,
  getPhase,
  hasTimedOut,
  VALID_TRANSITIONS,
  DEFAULT_SESSION_TIMEOUT_MS,
  REKEY_TIMEOUT_MS,
} from './state';

// Factory functions (low-level session creation)
export {
  createInitiatorSession,
  createResponderSession,
  HKDF_ADDITIONAL_RANGES,
  // Signal Protocol spec aliases (SCREAMING_SNAKE_CASE per Double Ratchet Section 3.3)
  RATCHET_INIT_ALICE,
  RATCHET_INIT_BOB,
} from './factory';

export type { InitiatorSessionInput, ResponderSessionInput } from './factory';

// SessionBuilder (high-level session establishment)
export { SessionBuilder } from './builder';

// SessionCipher (encrypt/decrypt operations)
export { SessionCipher } from './cipher';

// Ratchet operations
export {
  performDHRatchetStep,
  storeSkippedMessageKeys,
  cleanupExpiredMessageKeys,
} from './ratchet';

// Validation utilities
export {
  decodeIdentityKeyOrDummy,
  validateIdentityKey,
  validateSessionKeyOwnership,
  validateSessionStateIntegrity,
  checkSessionUsability,
  assertSessionUsability,
  isSelfSession,
  getMaxSkipForSession,
  DEFAULT_USABILITY_REQUIREMENTS,
  STRICT_USABILITY_REQUIREMENTS,
} from './validation';

export type { SessionUsabilityRequirements } from './validation';

export type {
  // SessionBuilder types
  SessionBuilderInitiatorInput,
  SessionBuilderInitiatorResult,
  SessionBuilderResponderInput,
  SessionBuilderResponderResult,
  KeyAgreementResult,
  ResponderKeyAgreementResult,
  // SessionCipher types
  SessionEstablishmentCallback,
  SessionCipherDependencies,
  SessionCipherConfig,
} from './types';
