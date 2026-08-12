/**
 * ML-KEM Braid Type Definitions
 *
 * Type definitions for the Signal Protocol ML-KEM Braid specification, a
 * bandwidth-optimized SCKA (Sparse Continuous Key Agreement) construction.
 *
 * @module ml-kem-braid/types
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented
 */

import type { Encoder } from './rs';

// =============================================================================
// Protocol Constants
// =============================================================================

/**
 * ML-KEM-768 key sizes (bytes)
 * SPQR uses ML-KEM-768 for bandwidth efficiency
 */
export {};
export const MLKEM_768_SIZES = {
  /** Encapsulation key seed size */
  EK_SEED_SIZE: 32,
  /** Encapsulation key vector size */
  EK_VECTOR_SIZE: 1152,
  /** Total public key size (seed + vector) */
  EK_TOTAL_SIZE: 1184,
  /** Decapsulation (private) key size */
  DK_SIZE: 2400,
  /** First ciphertext component size */
  CT1_SIZE: 960,
  /** Second ciphertext component (reconciliation) size */
  CT2_SIZE: 128,
  /** Total ciphertext size */
  CT_TOTAL_SIZE: 1088,
  /** Shared secret size */
  SS_SIZE: 32,
} as const;

/**
 * Protocol-level constants
 *
 * Note: Reed-Solomon encoding limits (POLYNOMIAL_LIMITS.MAX_MESSAGE_SIZE, etc.)
 * are internal to rs/polynomial.ts. The PolyEncoder validates these limits.
 */
export const PROTOCOL_CONSTANTS = {
  /** Header size (ek_seed + hek hash) */
  HEADER_SIZE: 64,
  /** MAC size (HMAC-SHA256) */
  MAC_SIZE: 32,
  /** Chunk size for erasure coding */
  CHUNK_SIZE: 32,
  /** Protocol domain separator */
  PROTOCOL_INFO: 'Signal_PQCKA_V1_MLKEM768',
} as const;

// =============================================================================
// State Machine States
// =============================================================================

/**
 * ML-KEM Braid State Machine States
 *
 * The protocol uses an 11-state machine to manage chunk transmission.
 *
 */
export type MLKEMBraidState =
  // Alice's states (initiator)
  | 'KeysUnsampled' // Ready to sample new keypair
  | 'KeysSampled' // Sending header, awaiting ct1
  | 'HeaderSent' // Sending ek_vector, receiving ct1
  | 'Ct1Received' // Received ct1, still sending ek_vector
  | 'EkSentCt1Received' // Sent ek_vector, receiving ct2

  // Bob's states (responder)
  | 'NoHeaderReceived' // Awaiting header from next epoch
  | 'HeaderReceived' // Received header, ready to sample ct1
  | 'Ct1Sampled' // Sending ct1, receiving ek_vector
  | 'EkReceivedCt1Sampled' // Received ek_vector, still sending ct1
  | 'Ct1Acknowledged' // CT1 acknowledged, receiving ek_vector
  | 'Ct2Sampled'; // Sending ct2 chunks

/** States where the agent is in Alice (key generator) role */
export const ALICE_STATES: ReadonlySet<MLKEMBraidState> = new Set([
  'KeysUnsampled',
  'KeysSampled',
  'HeaderSent',
  'Ct1Received',
  'EkSentCt1Received',
]);

/** States where the agent is in Bob (encapsulator) role */
export const BOB_STATES: ReadonlySet<MLKEMBraidState> = new Set([
  'NoHeaderReceived',
  'HeaderReceived',
  'Ct1Sampled',
  'EkReceivedCt1Sampled',
  'Ct1Acknowledged',
  'Ct2Sampled',
]);

/**
 * All valid states as an array for validation
 */
export const ALL_STATES: readonly MLKEMBraidState[] = [
  'KeysUnsampled',
  'KeysSampled',
  'HeaderSent',
  'Ct1Received',
  'EkSentCt1Received',
  'NoHeaderReceived',
  'HeaderReceived',
  'Ct1Sampled',
  'EkReceivedCt1Sampled',
  'Ct1Acknowledged',
  'Ct2Sampled',
] as const;

// =============================================================================
// Message Types
// =============================================================================

/**
 * ML-KEM Braid message type enumeration
 */
export enum MessageType {
  /** No SCKA data (passthrough) */
  None = 0,
  /** Header chunk */
  Hdr = 1,
  /** Encapsulation key vector chunk */
  Ek = 2,
  /** Ek chunk + CT1 acknowledgment */
  EkCt1Ack = 3,
  /** CT1 acknowledgment only */
  Ct1Ack = 4,
  /** First ciphertext chunk */
  Ct1 = 5,
  /** Second ciphertext chunk */
  Ct2 = 6,
}

/**
 * Version capability for protocol negotiation.
 *
 * Sent in first message(s) during session establishment.
 * Allows peers to confirm protocol version (V1=PQ hybrid).
 */
export interface VersionCapability {
  /** Maximum version we support */
  maxVersion: 'v1';
  /** Minimum version we accept */
  minVersion: 'v1';
}

/**
 * ML-KEM Braid protocol message
 */
export interface MLKEMBraidMessage {
  /** Current negotiation epoch (uint64) */
  epoch: bigint;
  /** Message type */
  type: MessageType;
  /** Chunk index for out-of-order delivery support (0-based) */
  chunkIndex?: number;
  /** Erasure code chunk (when applicable) */
  data?: Uint8Array;
  /** Version capability (only during negotiation) */
  versionCapability?: VersionCapability;
}

// =============================================================================
// Protocol State
// =============================================================================

/**
 * Authenticator state for message authentication
 */
export interface AuthenticatorState {
  /** Root key (32 bytes), ratcheted per epoch */
  root_key: Uint8Array;
  /** MAC key (32 bytes), derived from root_key */
  mac_key: Uint8Array;
}

/**
 * Decoder state for erasure-coded message reconstruction
 */
export interface DecoderState {
  /** Number of chunks received so far */
  receivedChunks: number;
  /** Minimum chunks required for reconstruction */
  requiredChunks: number;
  /** Expected message size in bytes */
  messageSize: number;
  /** Received chunk data indexed by position */
  chunks: Map<number, Uint8Array>;
}

/**
 * Encoder state for erasure-coded message transmission
 */
export interface EncoderState {
  /** Original data to encode */
  data: Uint8Array;
  /** Current chunk index */
  currentChunk: number;
  /** Total chunks (including parity) */
  totalChunks: number;
  /** Whether all systematic chunks have been sent */
  isComplete: boolean;
  /** Cached encoder instance for O(1) chunk retrieval */
  encoder?: Encoder;
}

// =============================================================================
// Role-Specific State Types (Recommended)
// =============================================================================

/**
 * Base state shared by both Alice and Bob
 */
export interface MLKEMBraidBaseState {
  /** Current state machine state */
  state: MLKEMBraidState;
  /** Current epoch number */
  epoch: bigint;
  /** Authenticator state */
  auth: AuthenticatorState;
}

/**
 * The complete state of one ML-KEM Braid participant, in either role.
 *
 * The ML-KEM Braid specification calls a protocol participant an agent,
 * and this name follows it. The name also separates this type from
 * `MLKEMBraidState`, which is the 11-state machine position that the
 * `state` field holds.
 *
 * The state name determines the current role, so this type carries no
 * `role` field. This matches the `SPQR` pattern, where the state variant
 * is the role. Call `isInAliceRole(state)` or `isInBobRole(state)` to read
 * the role.
 */
export interface MLKEMBraidAgentState extends MLKEMBraidBaseState {
  // The role comes from `state`, which ALICE_STATES and BOB_STATES partition.

  // ----- KEM State (populated in Alice role states) -----

  /** Decapsulation key (private, 2400 bytes) */
  dk?: Uint8Array;
  /** Encapsulation key seed (32 bytes) */
  ek_seed?: Uint8Array;
  /** Encapsulation key vector (1152 bytes) */
  ek_vector?: Uint8Array;
  /** Specification HEK: SHA3-256(ek_seed || ek_vector) */
  hek?: Uint8Array;

  // ----- Encapsulation State (populated in Bob role states) -----

  /** One-shot Encaps1 state; owned bytes are consumed and best-effort overwritten by Encaps2. */
  encaps_secret?: Uint8Array;
  /** First ciphertext component (960 bytes) */
  ct1?: Uint8Array;
  /** Second ciphertext component (128 bytes) */
  ct2?: Uint8Array;
  /** CT1 copy stored for combined MAC computation with CT2 (the reference implementation authenticates ct1||ct2) */
  ct1_for_mac?: Uint8Array;

  // ----- Encoders/Decoders (populated based on current state) -----

  /** Header encoder state */
  headerEncoder?: EncoderState;
  /** EK vector encoder state */
  ekEncoder?: EncoderState;
  /** CT1 decoder state */
  ct1Decoder?: DecoderState;
  /** CT2 decoder state */
  ct2Decoder?: DecoderState;
  /** Decoded CT1 stored for combined MAC verification with CT2 */
  ct1_decoded?: Uint8Array;
  /** Header decoder state */
  headerDecoder?: DecoderState;
  /** EK vector decoder state */
  ekDecoder?: DecoderState;
  /** CT1 encoder state */
  ct1Encoder?: EncoderState;
  /** CT2 encoder state */
  ct2Encoder?: EncoderState;
}

// =============================================================================
// Type Guards
// =============================================================================

/**
 * Check if agent is currently in Alice (key generator) role
 * @param state - Agent state to check
 * @returns true if state is an Alice role state
 */
export function isInAliceRole(state: MLKEMBraidAgentState): boolean {
  return ALICE_STATES.has(state.state);
}

/**
 * Check if agent is currently in Bob (encapsulator) role
 * @param state - Agent state to check
 * @returns true if state is a Bob role state
 */
export function isInBobRole(state: MLKEMBraidAgentState): boolean {
  return BOB_STATES.has(state.state);
}

// =============================================================================
// Function Return Types
// =============================================================================

/**
 * Output key from successful key agreement
 */
export interface OutputKey {
  /** Epoch this key is associated with */
  epoch: bigint;
  /** 32-byte epoch secret after KDF_OK; this is not raw ML-KEM output */
  epoch_secret: Uint8Array;
}

/**
 * Result of Send() operation
 */
export interface SendResult {
  /** Message to transmit */
  message: MLKEMBraidMessage;
  /** Highest epoch both parties know */
  sending_epoch: bigint;
  /** Optional key output (when key agreement completes) */
  output_key?: OutputKey;
}

/**
 * Result of Receive() operation
 */
export interface ReceiveResult {
  /** Highest epoch sender possessed */
  receiving_epoch: bigint;
  /** Optional key output (when key agreement completes) */
  output_key?: OutputKey;
}

// =============================================================================
// Incremental KEM Interfaces
// =============================================================================

/**
 * Result of KeyGen operation
 */
export interface KeyGenResult {
  /** Decapsulation key (private, 2400 bytes) */
  dk: Uint8Array;
  /** Encapsulation key seed (32 bytes) */
  ek_seed: Uint8Array;
  /** Encapsulation key vector (1152 bytes) */
  ek_vector: Uint8Array;
  /** Specification public-key commitment SHA3-256(ek_seed || ek_vector), 32 bytes */
  hek: Uint8Array;
}

/**
 * Result of Encaps1 operation
 */
export interface Encaps1Result {
  /** Encapsulation secret (internal, keep secret) */
  encaps_secret: Uint8Array;
  /** First ciphertext component (960 bytes) */
  ct1: Uint8Array;
  /** Shared secret (32 bytes) */
  shared_secret: Uint8Array;
}

/**
 * Incremental ML-KEM interface
 *
 * The braid state machine depends on a two-phase encapsulation seam that
 * exposes the intermediate secret and ciphertext component.
 */
export interface IIncrementalKEM {
  /**
   * Generate key pair with separated components
   * @param randomness - 32 bytes of randomness
   */
  KeyGen(randomness: Uint8Array): Promise<KeyGenResult>;

  /**
   * Phase 1: Encapsulate using only header
   * @param ek_seed - 32-byte encapsulation key seed
   * @param hek - Specification HEK: SHA3-256(ek_seed || ek_vector), 32 bytes
   * @param randomness - 32 bytes of randomness
   */
  Encaps1(ek_seed: Uint8Array, hek: Uint8Array, randomness: Uint8Array): Promise<Encaps1Result>;

  /**
   * Phase 2: Complete encapsulation using ek_vector
   * @param encaps_secret - Internal state from Encaps1
   * @param ek_seed - 32-byte encapsulation key seed
   * @param ek_vector - 1152-byte encapsulation key vector
   * @returns ct2 reconciliation (128 bytes)
   */
  Encaps2(
    encaps_secret: Uint8Array,
    ek_seed: Uint8Array,
    ek_vector: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Decapsulate using ct1 + ct2
   * @param dk - Decapsulation key (2400 bytes)
   * @param ct1 - First ciphertext (960 bytes)
   * @param ct2 - Second ciphertext (128 bytes)
   * @returns shared_secret (32 bytes)
   */
  Decaps(dk: Uint8Array, ct1: Uint8Array, ct2: Uint8Array): Promise<Uint8Array>;
}

// =============================================================================
// Authenticator Interface
// =============================================================================

/**
 * Ratcheted authenticator interface
 */
export interface IAuthenticator {
  /**
   * Initialize authenticator for new session
   * @param state - Authenticator state to initialize
   * @param epoch - Initial epoch number
   * @param initial_key - Initial shared secret from PQXDH
   */
  Init(state: AuthenticatorState, epoch: bigint, initial_key: Uint8Array): Promise<void>;

  /**
   * Update authenticator for new epoch
   * @param state - Authenticator state to update
   * @param epoch - New epoch number
   * @param key - Shared secret for this epoch
   */
  Update(state: AuthenticatorState, epoch: bigint, key: Uint8Array): Promise<void>;

  /**
   * Generate MAC for header
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param header - Header data
   * @returns 32-byte MAC
   */
  MacHdr(state: AuthenticatorState, epoch: bigint, header: Uint8Array): Uint8Array;

  /**
   * Generate MAC for ciphertext
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param ciphertext - Ciphertext data (ct1 or ct2)
   * @returns 32-byte MAC
   */
  MacCt(state: AuthenticatorState, epoch: bigint, ciphertext: Uint8Array): Uint8Array;

  /**
   * Verify header MAC
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param header - Header data
   * @param expected_mac - Expected MAC value
   * @throws Error if MAC verification fails
   */
  VfyHdr(
    state: AuthenticatorState,
    epoch: bigint,
    header: Uint8Array,
    expected_mac: Uint8Array
  ): void;

  /**
   * Verify ciphertext MAC
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param ciphertext - Ciphertext data
   * @param expected_mac - Expected MAC value
   * @throws Error if MAC verification fails
   */
  VfyCt(
    state: AuthenticatorState,
    epoch: bigint,
    ciphertext: Uint8Array,
    expected_mac: Uint8Array
  ): void;
}

// =============================================================================
// State Machine Interface
// =============================================================================

/**
 * ML-KEM Braid state machine interface
 */
export interface IMLKEMBraidStateMachine {
  /**
   * Initialize Alice (initiator) state
   * @param initial_shared_secret - Shared secret from PQXDH
   */
  InitAlice(initial_shared_secret: Uint8Array): Promise<MLKEMBraidAgentState>;

  /**
   * Initialize Bob (responder) state
   * @param initial_shared_secret - Shared secret from PQXDH
   */
  InitBob(initial_shared_secret: Uint8Array): Promise<MLKEMBraidAgentState>;

  /**
   * Process send operation
   * @param state - Current agent state (will be mutated)
   */
  Send(state: MLKEMBraidAgentState): Promise<SendResult>;

  /**
   * Process receive operation
   * @param state - Current agent state (will be mutated)
   * @param message - Received message
   */
  Receive(state: MLKEMBraidAgentState, message: MLKEMBraidMessage): Promise<ReceiveResult>;
}
