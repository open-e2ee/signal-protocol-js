/**
 * Session State Machine Types (Layer 5)
 *
 * Defines typed session phases and state transitions for the Signal Protocol.
 * These types enforce valid operations at compile time based on session state.
 *
 * State Machine (Signal Protocol Session Lifecycle):
 * ```
 * ┌───────────────┐
 * │ Uninitialized │
 * └───────┬───────┘
 *         │ initialize()
 *         ▼
 * ┌───────────────┐
 * │    Pending    │ ← X3DH/PQXDH in progress
 * └───────┬───────┘
 *         │ receivePreKeyMessage() or sendFirstMessage()
 *         ▼
 * ┌───────────────┐     rotateKeys()    ┌──────────────┐
 * │    Active     │ ←─────────────────→ │   Rekeying   │
 * └───────┬───────┘                     └──────────────┘
 *         │ timeout / explicit close
 *         ▼
 * ┌───────────────┐
 * │    Expired    │
 * └───────────────┘
 * ```
 *
 * Valid Transitions:
 * - uninitialized → pending: On SessionBuilder.build()
 * - pending → active: On first message exchange
 * - active → rekeying: On key rotation
 * - rekeying → active: On rotation complete
 * - active → expired: On session timeout
 *
 * @see https://signal.org/docs/specifications/x3dh/#session-state
 * @see https://signal.org/docs/specifications/doubleratchet/#session-initialization
 */

import type { ProtocolAddress } from '../../types/address';
import type { CompositeIdentityV1, IdentityKeyPair, PublicKey, PrivateKey } from '../../keys';
import type { Base64 } from '../../types/utils';
import type { RootKey, ChainKey } from './keys';
import type { ReceiverChain } from '../../types/session';

// ============================================================================
// Session Phase Enum
// ============================================================================

/**
 * Session lifecycle phases.
 *
 * Each phase represents a distinct state in the session lifecycle with
 * specific allowed operations.
 */
export {};
export type SessionPhase =
  | 'uninitialized' // No keys established
  | 'pending' // X3DH/PQXDH in progress, waiting for first message
  | 'active' // Session fully established, can encrypt/decrypt
  | 'rekeying' // Key rotation in progress
  | 'expired'; // Session timed out or explicitly closed

// ============================================================================
// Phase-Specific Session States (Discriminated Union)
// ============================================================================

/**
 * Base session metadata shared across all phases.
 */
interface SessionMetadataBase {
  /** Unique session identifier */
  sessionId: string;
  /** Our address */
  localAddress: ProtocolAddress;
  /** Remote party's address */
  remoteAddress: ProtocolAddress;
  /** Our identity key pair */
  identityKeyPair: IdentityKeyPair;
  /** Local and remote composite identity trust objects. */
  localIdentity: CompositeIdentityV1;
  remoteIdentity: CompositeIdentityV1;
  /** Session creation timestamp */
  createdAt: number;
}

/**
 * Uninitialized session state.
 *
 * The session exists, and no key exchange started yet.
 * Only valid operation: initialize()
 */
export interface UninitializedSession extends SessionMetadataBase {
  phase: 'uninitialized';
}

/**
 * Pending session state.
 *
 * X3DH/PQXDH key exchange is in progress.
 * Waiting for first message to complete session establishment.
 *
 * Valid operations: sendFirstMessage(), receivePreKeyMessage()
 */
export interface PendingSession extends SessionMetadataBase {
  phase: 'pending';
  /** Root key from key exchange */
  RK: RootKey;
  /** Our ephemeral DH key pair (for initiator) */
  ephemeralKeyPair?: { publicKey: PublicKey; privateKey: PrivateKey };
  /** IDs of prekeys used (for initiator to build PreKeyMessage) */
  usedSignedPreKeyId?: number;
  usedOneTimePreKeyId?: number;
  usedKyberPreKeyId?: number;
  usedKemOneTimePreKeyId?: number;
  /** Kyber ciphertext for last-resort prekey (for initiator to send in PreKeyMessage) */
  kyberCiphertext?: Base64;
  /** Kyber ciphertext for one-time KEM prekey (for initiator to send in PreKeyMessage) */
  kemOneTimePreKeyCiphertext?: Base64;
  /** Whether we initiated the session */
  isInitiator: boolean;
}

/**
 * Active session state.
 *
 * Session is fully established and operational.
 * Can encrypt and decrypt messages.
 *
 * Note: Uses Section 3 variant (plaintext headers + MAC authentication).
 * Header encryption keys (HKs, HKr, NHKs, NHKr) are not used.
 *
 * Valid operations: encrypt(), decrypt(), rotateKeys()
 */
export interface ActiveSession extends SessionMetadataBase {
  phase: 'active';
  /** Root Key */
  RK: RootKey;
  /** Our DH ratchet key pair */
  DHs: { publicKey: PublicKey; privateKey: PrivateKey };
  /** Remote party's DH ratchet public key */
  DHr: PublicKey;
  /** Sending chain key */
  CKs: ChainKey;
  /** Receiving chain key */
  CKr: ChainKey;
  /** Messages sent in current sending chain */
  Ns: number;
  /** Messages received in current receiving chain */
  Nr: number;
  /** Previous chain length */
  PN: number;
  /** Receiver chains with skipped message keys */
  receiverChains: ReceiverChain[];
  /** Last activity timestamp */
  lastUsedAt: number;
  /**
   * Whether we received at least one message in this session.
   *
   * Unacknowledged PreKey sessions expire after 30 days
   * (MAX_UNACKNOWLEDGED_SESSION_AGE).
   *
   * @default false for initiator sessions, true for responder sessions
   */
  hasReceivedMessage?: boolean;
}

/**
 * Rekeying session state.
 *
 * The session rotates its keys.
 * Limited operations until rotation completes.
 *
 * Note: Uses Section 3 variant (plaintext headers + MAC authentication).
 * Header encryption keys are not used.
 *
 * Valid operations: completeRekey(), decrypt() (for in-flight messages)
 */
export interface RekeyingSession extends Omit<ActiveSession, 'phase'> {
  phase: 'rekeying';
  /** Old keys that the session phases out */
  previousDHr?: PublicKey;
  previousCKr?: ChainKey;
  /** Rekey initiated timestamp */
  rekeyStartedAt: number;
}

/**
 * Expired session state.
 *
 * The session timed out, or the caller closed it explicitly.
 * No operations allowed except archive/delete.
 *
 * Valid operations: archive(), delete()
 */
export interface ExpiredSession extends SessionMetadataBase {
  phase: 'expired';
  /** When session expired */
  expiredAt: number;
  /** Reason for expiration */
  expirationReason: 'timeout' | 'explicit_close' | 'error' | 'superseded';
  /** Last known root key (for potential recovery) */
  lastRK?: RootKey;
}

/**
 * Union type for all session states.
 *
 * Use type guards to narrow to specific phases.
 */
export type TypedSessionState =
  | UninitializedSession
  | PendingSession
  | ActiveSession
  | RekeyingSession
  | ExpiredSession;

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Check if session is in uninitialized phase.
 */
export function isUninitialized(state: TypedSessionState): state is UninitializedSession {
  return state.phase === 'uninitialized';
}

/**
 * Check if session is in pending phase.
 */
export function isPending(state: TypedSessionState): state is PendingSession {
  return state.phase === 'pending';
}

/**
 * Check if session is in active phase.
 */
export function isActive(state: TypedSessionState): state is ActiveSession {
  return state.phase === 'active';
}

/**
 * Check if session is in rekeying phase.
 */
export function isRekeying(state: TypedSessionState): state is RekeyingSession {
  return state.phase === 'rekeying';
}

/**
 * Check whether the session expired.
 */
export function isExpired(state: TypedSessionState): state is ExpiredSession {
  return state.phase === 'expired';
}

/**
 * Check if session can encrypt messages.
 *
 * Only active sessions can encrypt.
 */
export function canEncrypt(state: TypedSessionState): state is ActiveSession {
  return state.phase === 'active';
}

/**
 * Check if session can decrypt messages.
 *
 * Active and rekeying sessions can decrypt.
 */
export function canDecrypt(state: TypedSessionState): state is ActiveSession | RekeyingSession {
  return state.phase === 'active' || state.phase === 'rekeying';
}

/**
 * Check whether the session can communicate.
 *
 * Active and rekeying sessions can communicate.
 */
export function isEstablished(state: TypedSessionState): state is ActiveSession | RekeyingSession {
  return state.phase === 'active' || state.phase === 'rekeying';
}

/**
 * Check if session needs initialization.
 */
export function needsInitialization(state: TypedSessionState): state is UninitializedSession {
  return state.phase === 'uninitialized';
}

/**
 * Check whether the session waits for the first message.
 */
export function awaitingFirstMessage(state: TypedSessionState): state is PendingSession {
  return state.phase === 'pending';
}

// ============================================================================
// State Transition Functions
// ============================================================================

/**
 * Valid state transitions.
 */
export const VALID_TRANSITIONS: Record<SessionPhase, SessionPhase[]> = {
  uninitialized: ['pending'],
  pending: ['active'],
  active: ['rekeying', 'expired'],
  rekeying: ['active', 'expired'],
  expired: [], // Terminal state
};

/**
 * Check if a state transition is valid.
 *
 * @param from - Current phase
 * @param to - Target phase
 * @returns true if transition is valid
 */
export function isValidTransition(from: SessionPhase, to: SessionPhase): boolean {
  return VALID_TRANSITIONS[from].includes(to);
}

/**
 * Get the current phase from a session state.
 */
export function getPhase(state: TypedSessionState): SessionPhase {
  return state.phase;
}

// ============================================================================
// Session Timeout Configuration
// ============================================================================

/**
 * Default session timeout (30 days in milliseconds).
 *
 * Sessions without activity for this duration should transition to expired.
 */
export const DEFAULT_SESSION_TIMEOUT_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Rekey timeout (5 minutes in milliseconds).
 *
 * If rekey does not complete within this time, session should error.
 */
export const REKEY_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Check whether the session timed out.
 *
 * @param state - Session state
 * @param timeout - Timeout duration in ms (default: 30 days)
 * @returns true if the session exceeded the timeout
 */
export function hasTimedOut(
  state: TypedSessionState,
  timeout: number = DEFAULT_SESSION_TIMEOUT_MS
): boolean {
  if (state.phase === 'expired') return true;
  if (state.phase === 'uninitialized') return false;

  const lastActivity = 'lastUsedAt' in state ? state.lastUsedAt : state.createdAt;
  return Date.now() - lastActivity > timeout;
}
