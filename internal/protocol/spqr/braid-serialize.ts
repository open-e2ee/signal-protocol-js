/**
 * ML-KEM Braid State Serialization
 *
 * @module spqr/braid-serialize
 *
 * Provides serialization and deserialization of ML-KEM Braid agent state
 * for persistence. Extracted from braid.ts for modularity.
 *
 * WARNING: Serialized state contains sensitive cryptographic material.
 * Ensure it is stored securely (encrypted at rest).
 */

import {
  bytesToHex,
  hexToBytes,
  type AuthenticatorJSON,
  type ChunkJSON,
  type MLKEMBraidMessageJSON,
  serializeMessageJSON,
  deserializeMessageJSON,
} from './ml-kem-braid/serialize';
import {
  isInAliceRole,
  isInBobRole,
  ALICE_STATES,
  BOB_STATES,
  ALL_STATES,
  MLKEM_768_SIZES,
  PROTOCOL_CONSTANTS,
} from './ml-kem-braid/types';
import type { MLKEMBraidAgentState, EncoderState, DecoderState } from './ml-kem-braid/types';
import {
  BRAID_ENCODER_CURSOR_MAX,
  assertBraidChunkIndex,
  assertBraidEncoderCursor,
} from './ml-kem-braid/chunk-domain';

// Re-export message serialization for convenience
export {};
export { MLKEMBraidMessageJSON, serializeMessageJSON, deserializeMessageJSON };

// =============================================================================
// JSON Type Definitions
// =============================================================================

/**
 * JSON representation of encoder state
 */
export interface EncoderStateJSON {
  /** Original data as hex */
  data: string;
  /** Current chunk index */
  currentChunk: number;
  /** Total chunks */
  totalChunks: number;
  /** Whether systematic chunks are complete */
  isComplete: boolean;
}

/**
 * JSON representation of decoder state
 */
export interface DecoderStateJSON {
  /** Number of chunks received */
  receivedChunks: number;
  /** Required chunks for reconstruction */
  requiredChunks: number;
  /** Expected message size */
  messageSize: number;
  /** Received chunks */
  chunks: ChunkJSON[];
}

/**
 * JSON representation of ML-KEM Braid agent state
 */
export interface MLKEMBraidAgentStateJSON {
  /** State machine state name */
  state: string;
  /** Current epoch (bigint as string) */
  epoch: string;
  /** Authenticator state */
  auth: AuthenticatorJSON;

  // Alice-specific fields (when state is an Alice state)
  /** Decapsulation key (2400 bytes) */
  dk?: string;
  /** EK seed (32 bytes) */
  ek_seed?: string;
  /** EK vector (1152 bytes) */
  ek_vector?: string;
  /** Header commitment (32 bytes) */
  hek?: string;
  /** Header encoder */
  headerEncoder?: EncoderStateJSON;
  /** EK encoder */
  ekEncoder?: EncoderStateJSON;
  /** CT1 decoder */
  ct1Decoder?: DecoderStateJSON;
  /** CT2 decoder */
  ct2Decoder?: DecoderStateJSON;
  /** Decoded CT1 for MAC verification */
  ct1_decoded?: string;

  // Bob-specific fields (when state is a Bob state)
  /** Encapsulation secret (internal) */
  encaps_secret?: string;
  /** CT1 ciphertext component */
  ct1?: string;
  /** CT2 ciphertext component */
  ct2?: string;
  /** CT1 for MAC computation */
  ct1_for_mac?: string;
  /** Shared secret */
  shared_secret?: string;
  /** Header decoder */
  headerDecoder?: DecoderStateJSON;
  /** EK decoder */
  ekDecoder?: DecoderStateJSON;
  /** CT1 encoder */
  ct1Encoder?: EncoderStateJSON;
  /** CT2 encoder */
  ct2Encoder?: EncoderStateJSON;
}

const MAX_RESTORED_STATE_BYTES = 1024 * 1024;
const UINT64_MAX = (1n << 64n) - 1n;

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertInteger(value: unknown, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}`);
  }
  return value as number;
}

function decodeExactHex(value: unknown, label: string, expectedLength: number): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be canonical hex`);
  const decoded = hexToBytes(value);
  if (decoded.length !== expectedLength) {
    throw new Error(`${label} must contain exactly ${expectedLength} bytes`);
  }
  return decoded;
}

function validateEncoderStateJSON(value: unknown, label: string): void {
  assertRecord(value, label);
  if (typeof value.data !== 'string') throw new Error(`${label}.data must be canonical hex`);
  const data = hexToBytes(value.data);
  if (data.length === 0 || data.length > 1152) {
    throw new Error(`${label}.data must contain between 1 and 1152 bytes`);
  }
  // totalChunks is the initial delivery estimate; streaming parity generation
  // may advance currentChunk beyond it while waiting for peer acknowledgement.
  assertInteger(value.totalChunks, `${label}.totalChunks`, 1, BRAID_ENCODER_CURSOR_MAX);
  assertBraidEncoderCursor(value.currentChunk, `${label}.currentChunk`);
  if (typeof value.isComplete !== 'boolean') throw new Error(`${label}.isComplete must be boolean`);
}

function validateDecoderStateJSON(value: unknown, label: string): void {
  assertRecord(value, label);
  const messageSize = assertInteger(value.messageSize, `${label}.messageSize`, 1, 1152);
  const required = Math.ceil(messageSize / PROTOCOL_CONSTANTS.CHUNK_SIZE);
  if (value.requiredChunks !== required) {
    throw new Error(`${label}.requiredChunks does not match messageSize`);
  }
  if (!Array.isArray(value.chunks) || value.chunks.length > required) {
    throw new Error(`${label}.chunks exceeds the required bounded chunk count`);
  }
  if (value.receivedChunks !== value.chunks.length) {
    throw new Error(`${label}.receivedChunks does not match chunks`);
  }
  const indices = new Set<number>();
  for (const [position, chunk] of value.chunks.entries()) {
    assertRecord(chunk, `${label}.chunks[${position}]`);
    const index = assertBraidChunkIndex(chunk.index, `${label}.chunks[${position}].index`);
    if (indices.has(index)) throw new Error(`${label} contains duplicate chunk index ${index}`);
    indices.add(index);
    decodeExactHex(
      chunk.data,
      `${label}.chunks[${position}].data`,
      PROTOCOL_CONSTANTS.CHUNK_SIZE
    );
  }
}

function validateBraidStateJSON(value: unknown): asserts value is MLKEMBraidAgentStateJSON {
  assertRecord(value, 'Braid state');
  if (typeof value.state !== 'string' || !ALL_STATES.includes(value.state as never)) {
    throw new Error(`Unknown ML-KEM Braid state: ${String(value.state)}`);
  }
  if (typeof value.epoch !== 'string' || !/^(?:0|[1-9]\d*)$/.test(value.epoch)) {
    throw new Error('Braid epoch must use canonical unsigned decimal encoding');
  }
  const epoch = BigInt(value.epoch);
  if (epoch > UINT64_MAX) throw new Error('Braid epoch must fit in uint64');
  assertRecord(value.auth, 'Braid authenticator');
  decodeExactHex(value.auth.root_key, 'Braid authenticator root key', 32);
  decodeExactHex(value.auth.mac_key, 'Braid authenticator MAC key', 32);

  const exactByteFields: Record<string, number> = {
    dk: MLKEM_768_SIZES.DK_SIZE,
    ek_seed: MLKEM_768_SIZES.EK_SEED_SIZE,
    ek_vector: MLKEM_768_SIZES.EK_VECTOR_SIZE,
    hek: 32,
    encaps_secret: 1600,
    ct1: MLKEM_768_SIZES.CT1_SIZE,
    ct2: MLKEM_768_SIZES.CT2_SIZE,
    ct1_for_mac: MLKEM_768_SIZES.CT1_SIZE,
    ct1_decoded: MLKEM_768_SIZES.CT1_SIZE,
  };
  for (const [field, length] of Object.entries(exactByteFields)) {
    if (value[field] !== undefined) decodeExactHex(value[field], `Braid state ${field}`, length);
  }
  for (const field of ['headerEncoder', 'ekEncoder', 'ct1Encoder', 'ct2Encoder']) {
    if (value[field] !== undefined) validateEncoderStateJSON(value[field], `Braid state ${field}`);
  }
  for (const field of ['headerDecoder', 'ekDecoder', 'ct1Decoder', 'ct2Decoder']) {
    if (value[field] !== undefined) validateDecoderStateJSON(value[field], `Braid state ${field}`);
  }

  const state = value.state as MLKEMBraidAgentState['state'];
  if (!ALICE_STATES.has(state) && !BOB_STATES.has(state)) {
    throw new Error(`Unknown ML-KEM Braid role for state: ${state}`);
  }
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Serialize encoder state to JSON format
 */
function serializeEncoderState(state: EncoderState): EncoderStateJSON {
  return {
    data: bytesToHex(state.data),
    currentChunk: state.currentChunk,
    totalChunks: state.totalChunks,
    isComplete: state.isComplete,
  };
}

/**
 * Deserialize encoder state from JSON format
 *
 * Note: The `encoder` field (cached instance) is NOT restored - it will be
 * recreated lazily when needed. This is intentional for persistence safety.
 */
function deserializeEncoderState(json: EncoderStateJSON): EncoderState {
  return {
    data: hexToBytes(json.data),
    currentChunk: json.currentChunk,
    totalChunks: json.totalChunks,
    isComplete: json.isComplete,
    // encoder is recreated lazily - not persisted
  };
}

/**
 * Serialize decoder state to JSON format
 */
function serializeDecoderState(state: DecoderState): DecoderStateJSON {
  const chunks: ChunkJSON[] = [];
  for (const [index, data] of state.chunks) {
    chunks.push({ index, data: bytesToHex(data) });
  }

  return {
    receivedChunks: state.receivedChunks,
    requiredChunks: state.requiredChunks,
    messageSize: state.messageSize,
    chunks,
  };
}

/**
 * Deserialize decoder state from JSON format
 */
function deserializeDecoderState(json: DecoderStateJSON): DecoderState {
  const chunks = new Map<number, Uint8Array>();
  for (const chunk of json.chunks) {
    chunks.set(chunk.index, hexToBytes(chunk.data));
  }

  return {
    receivedChunks: json.receivedChunks,
    requiredChunks: json.requiredChunks,
    messageSize: json.messageSize,
    chunks,
  };
}

// =============================================================================
// Main Serialization Functions
// =============================================================================

/**
 * Serialize ML-KEM Braid agent state to JSON for persistence.
 *
 * This enables app backgrounding/restoration by capturing the full state
 * machine state including:
 * - Current state and epoch
 * - Authenticator keys
 * - Encoder/decoder progress
 * - Cryptographic material (keys, ciphertexts)
 *
 * WARNING: The serialized state contains sensitive cryptographic material.
 * Ensure it is stored securely (encrypted at rest).
 *
 * @param state - Agent state to serialize
 * @returns JSON string representation
 *
 * @example
 * ```typescript
 * const json = serializeBraidAgentState(spqrState.braidState);
 * await secureStorage.set('spqr_braid_state', json);
 * ```
 */
export function serializeBraidAgentState(state: MLKEMBraidAgentState): string {
  const json: MLKEMBraidAgentStateJSON = {
    state: state.state,
    epoch: state.epoch.toString(),
    auth: {
      root_key: bytesToHex(state.auth.root_key),
      mac_key: bytesToHex(state.auth.mac_key),
    },
  };

  if (isInAliceRole(state)) {
    // Alice-specific fields
    if (state.dk) json.dk = bytesToHex(state.dk);
    if (state.ek_seed) json.ek_seed = bytesToHex(state.ek_seed);
    if (state.ek_vector) json.ek_vector = bytesToHex(state.ek_vector);
    if (state.hek) json.hek = bytesToHex(state.hek);

    if (state.headerEncoder) {
      json.headerEncoder = serializeEncoderState(state.headerEncoder);
    }
    if (state.ekEncoder) {
      json.ekEncoder = serializeEncoderState(state.ekEncoder);
    }
    if (state.ct1Decoder) {
      json.ct1Decoder = serializeDecoderState(state.ct1Decoder);
    }
    if (state.ct2Decoder) {
      json.ct2Decoder = serializeDecoderState(state.ct2Decoder);
    }
    if (state.ct1_decoded) {
      json.ct1_decoded = bytesToHex(state.ct1_decoded);
    }
  } else if (isInBobRole(state)) {
    // Bob-specific fields
    if (state.ek_seed) {
      json.ek_seed = bytesToHex(state.ek_seed);
    }
    if (state.ek_vector) {
      json.ek_vector = bytesToHex(state.ek_vector);
    }
    if (state.hek) {
      json.hek = bytesToHex(state.hek);
    }
    if (state.encaps_secret) {
      json.encaps_secret = bytesToHex(state.encaps_secret);
    }
    if (state.ct1) {
      json.ct1 = bytesToHex(state.ct1);
    }
    if (state.ct2) {
      json.ct2 = bytesToHex(state.ct2);
    }
    if (state.ct1_for_mac) {
      json.ct1_for_mac = bytesToHex(state.ct1_for_mac);
    }

    if (state.headerDecoder) {
      json.headerDecoder = serializeDecoderState(state.headerDecoder);
    }
    if (state.ekDecoder) {
      json.ekDecoder = serializeDecoderState(state.ekDecoder);
    }
    if (state.ct1Encoder) {
      json.ct1Encoder = serializeEncoderState(state.ct1Encoder);
    }
    if (state.ct2Encoder) {
      json.ct2Encoder = serializeEncoderState(state.ct2Encoder);
    }
  }

  return JSON.stringify(json);
}

/**
 * Deserialize ML-KEM Braid agent state from JSON.
 *
 * Restores state machine state for resuming after app backgrounding.
 *
 * @param jsonStr - JSON string from serializeBraidAgentState
 * @returns Restored agent state
 *
 * @example
 * ```typescript
 * const json = await secureStorage.get('spqr_braid_state');
 * const braidState = deserializeBraidAgentState(json);
 * spqrState.braidState = braidState;
 * ```
 */
export function deserializeBraidAgentState(jsonStr: string): MLKEMBraidAgentState {
  if (new TextEncoder().encode(jsonStr).length > MAX_RESTORED_STATE_BYTES) {
    throw new Error(`Braid state exceeds ${MAX_RESTORED_STATE_BYTES}-byte input limit`);
  }
  const parsed: unknown = JSON.parse(jsonStr);
  validateBraidStateJSON(parsed);
  const json = parsed;
  const state = json.state as MLKEMBraidAgentState['state'];

  const baseState = {
    state,
    epoch: BigInt(json.epoch),
    auth: {
      root_key: hexToBytes(json.auth.root_key),
      mac_key: hexToBytes(json.auth.mac_key),
    },
  };

  if (ALICE_STATES.has(state)) {
    // Restore Alice state
    const aliceState: MLKEMBraidAgentState = {
      ...baseState,
      dk: json.dk ? hexToBytes(json.dk) : undefined,
      ek_seed: json.ek_seed ? hexToBytes(json.ek_seed) : undefined,
      ek_vector: json.ek_vector ? hexToBytes(json.ek_vector) : undefined,
      hek: json.hek ? hexToBytes(json.hek) : undefined,
    };

    if (json.headerEncoder) {
      aliceState.headerEncoder = deserializeEncoderState(json.headerEncoder);
    }
    if (json.ekEncoder) {
      aliceState.ekEncoder = deserializeEncoderState(json.ekEncoder);
    }
    if (json.ct1Decoder) {
      aliceState.ct1Decoder = deserializeDecoderState(json.ct1Decoder);
    }
    if (json.ct2Decoder) {
      aliceState.ct2Decoder = deserializeDecoderState(json.ct2Decoder);
    }
    if (json.ct1_decoded) {
      aliceState.ct1_decoded = hexToBytes(json.ct1_decoded);
    }

    return aliceState;
  } else {
    // Restore Bob state
    const bobState: MLKEMBraidAgentState = {
      ...baseState,
    };

    if (json.ek_seed) {
      bobState.ek_seed = hexToBytes(json.ek_seed);
    }
    if (json.ek_vector) {
      bobState.ek_vector = hexToBytes(json.ek_vector);
    }
    if (json.hek) {
      bobState.hek = hexToBytes(json.hek);
    }
    if (json.encaps_secret) {
      bobState.encaps_secret = hexToBytes(json.encaps_secret);
    }
    if (json.ct1) {
      bobState.ct1 = hexToBytes(json.ct1);
    }
    if (json.ct2) {
      bobState.ct2 = hexToBytes(json.ct2);
    }
    if (json.ct1_for_mac) {
      bobState.ct1_for_mac = hexToBytes(json.ct1_for_mac);
    }

    if (json.headerDecoder) {
      bobState.headerDecoder = deserializeDecoderState(json.headerDecoder);
    }
    if (json.ekDecoder) {
      bobState.ekDecoder = deserializeDecoderState(json.ekDecoder);
    }
    if (json.ct1Encoder) {
      bobState.ct1Encoder = deserializeEncoderState(json.ct1Encoder);
    }
    if (json.ct2Encoder) {
      bobState.ct2Encoder = deserializeEncoderState(json.ct2Encoder);
    }

    return bobState;
  }
}
