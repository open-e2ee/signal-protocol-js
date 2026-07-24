/**
 * ML-KEM Braid Protocol
 *
 * Bandwidth-optimized SCKA (Sparse Continuous Key Agreement) implementation
 * for the SPQR post-quantum ratchet.
 *
 * @module ml-kem-braid
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented
 *
 * ## Overview
 *
 * ML-KEM Braid is the chunked transmission variant of SCKA for SPQR.
 * It is designed for bandwidth-constrained environments (satellite, IoT, tactical)
 * where the standard 1,088-byte ML-KEM-768 ciphertext cannot be sent atomically.
 *
 * ## Features
 *
 * - 32-byte chunks (fits LoRaWAN, satellite payloads)
 * - Reed-Solomon erasure coding (GF(2^16) with 16-polynomial interleaving)
 * - 11-state protocol machine
 * - Parallel ct1/ek_vector transmission
 * - Incremental KEM operations
 * - MAC verification with HMAC-SHA256
 * - Best-effort clearing of owned sensitive byte arrays
 *
 * ## Architecture
 *
 * The state machine uses Reed-Solomon erasure coding for chunk recovery.
 */

// =============================================================================
// Type Exports
// =============================================================================
export {};
export type {
  // State machine
  MLKEMBraidState,
  MLKEMBraidAgentState,
  MLKEMBraidMessage,
  SendResult,
  ReceiveResult,

  // Authenticator
  AuthenticatorState,

  // Encoder/Decoder
  EncoderState,
  DecoderState,

  // Incremental KEM
  KeyGenResult,
  Encaps1Result,
  OutputKey,

  // Interfaces
  IIncrementalKEM,
  IAuthenticator,
  IMLKEMBraidStateMachine,
} from './types';

// Streaming encoder/decoder interfaces (from rs, see Reed-Solomon section below)

// =============================================================================
// Constant Exports
// =============================================================================

export {
  // ML-KEM-768 sizes
  MLKEM_768_SIZES,
  // Protocol constants
  PROTOCOL_CONSTANTS,
  // All valid states
  ALL_STATES,
  // Message types
  MessageType,
  // Type guards
  isInAliceRole,
  isInBobRole,
  ALICE_STATES,
  BOB_STATES,
} from './types';

export {
  BRAID_CHUNK_INDEX_MAX,
  BRAID_CHUNK_POINT_COUNT,
  BRAID_ENCODER_CURSOR_MAX,
} from './chunk-domain';

// =============================================================================
// Error Exports
// =============================================================================

export {
  // Base error class
  MLKEMBraidError,
  // Module-specific errors
  IncrementalKEMError,
  AuthenticatorError,
  StateTransitionError,
  ErasureError,
  KDFError,
  // Error codes
  ErrorCode,
} from './errors';

// =============================================================================
// State Machine
// =============================================================================

export { MLKEMBraidStateMachine, createStateMachine, STATE_TRANSITIONS } from './state-machine';

// =============================================================================
// Incremental KEM
// =============================================================================

export { IncrementalMLKEM768, createIncrementalKEM, computeHek } from './incremental-kem';

// =============================================================================
// Reed-Solomon erasure coding for ML-KEM Braid
// =============================================================================

export type { Encoder, Decoder, ErasureConfig, FieldSize } from './rs';

export {
  // Polynomial codec classes
  PolyEncoder,
  PolyDecoder,
  createEncoder,
  createDecoder,
  // GF(2^16) initialization
  initGF16,
  isGF16Ready,
  // Galois field exports
  createGF16,
  // Polynomial exports
  LagrangeInterpolator,
  Polynomial,
} from './rs';

// =============================================================================
// Authenticator
// =============================================================================

export {
  RatchetedAuthenticator,
  createAuthenticator,
  initAuthenticatorState,
} from './authenticator';

// =============================================================================
// KDF Functions
// =============================================================================

export { KDF_AUTH, KDF_OK, bytesToUint64, uint64ToBytes } from './kdf';

// =============================================================================
// Serialization (Multi-format: Binary, Protobuf, JSON)
// =============================================================================

export type {
  // JSON interfaces
  MLKEMBraidMessageJSON,
  ChunkJSON,
  AuthenticatorJSON,
  PolyEncoderJSON,
  PolyDecoderJSON,
} from './serialize';

export {
  // Initialization
  initSerialization,
  isSerializationReady,

  // Utility functions
  bytesToHex,
  hexToBytes,
  uint64ToBytesBE,
  bytesToUint64BE,
  uint16ToBytesLE,
  bytesToUint16LE,
  getMessageTypeName,
  getMessageTypeValue,

  // Binary format
  serializeShardBinary,
  deserializeShardBinary,
  serializeMessageBinary,
  deserializeMessageBinary,

  // Protobuf format
  serializeMessageProto,
  deserializeMessageProto,
  serializeAuthenticatorProto,
  deserializeAuthenticatorProto,
  serializeEncoderProto,
  deserializeEncoderProto,
  serializeDecoderProto,
  deserializeDecoderProto,

  // JSON format
  serializeMessageJSON,
  deserializeMessageJSON,
  serializeAuthenticatorJSON,
  deserializeAuthenticatorJSON,
  serializeEncoderJSON,
  deserializeEncoderJSON,
  serializeDecoderJSON,
  deserializeDecoderJSON,
} from './serialize';
