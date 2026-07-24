/**
 * ML-KEM Braid Multi-Format Serialization
 *
 * Supports three serialization formats:
 * - Binary: Raw Uint8Array for internal operations (lowest overhead)
 * - Protobuf: versioned ML-KEM Braid fields
 * - JSON: Human-readable for debugging, logging, and state persistence
 *
 * @module ml-kem-braid/serialize
 */

import protobuf from 'protobufjs';
import { assertBraidChunkIndex, assertBraidEncoderCursor } from './chunk-domain';
import { MessageType, PROTOCOL_CONSTANTS } from './types';
import type { MLKEMBraidMessage, AuthenticatorState } from './types';

// =============================================================================
// JSON Serialization Interfaces
// =============================================================================

/**
 * JSON representation of version capability
 */
export {};
export interface VersionCapabilityJSON {
  /** Maximum version we support */
  maxVersion: 'v1';
  /** Minimum version we accept */
  minVersion: 'v1';
}

/**
 * JSON representation of a protocol message
 */
export interface MLKEMBraidMessageJSON {
  /** Epoch as string (bigint serialization) */
  epoch: string;
  /** Message type name */
  type: string;
  /** Chunk index (optional) */
  index?: number;
  /** Data as hex string (optional) */
  data?: string;
  /** Version capability (optional, during negotiation) */
  versionCapability?: VersionCapabilityJSON;
}

/**
 * JSON representation of an erasure-coded chunk
 */
export interface ChunkJSON {
  /** Chunk index */
  index: number;
  /** Chunk data as hex string */
  data: string;
}

/**
 * JSON representation of authenticator state
 */
export interface AuthenticatorJSON {
  /** Root key as hex string */
  root_key: string;
  /** MAC key as hex string */
  mac_key: string;
}

/**
 * JSON representation of polynomial encoder state
 */
export interface PolyEncoderJSON {
  /** Current chunk index */
  idx: number;
  /** Evaluation points as hex strings */
  pts: string[];
  /** Polynomial coefficients as hex strings */
  polys: string[];
  /** Original message size */
  messageSize: number;
}

/**
 * JSON representation of polynomial decoder state
 */
export interface PolyDecoderJSON {
  /** Chunks needed for reconstruction */
  ptsNeeded: number;
  /** Number of polynomials (always 16) */
  polys: number;
  /** Received chunks */
  chunks: ChunkJSON[];
  /** Whether decoding is complete */
  isComplete: boolean;
  /** Expected message size */
  messageSize: number;
}

const MAX_WIRE_INPUT_BYTES = 64 * 1024;
const UINT64_MAX = (1n << 64n) - 1n;
const CHUNK_MESSAGE_TYPES = new Set<MessageType>([
  MessageType.Hdr,
  MessageType.Ek,
  MessageType.EkCt1Ack,
  MessageType.Ct1,
  MessageType.Ct2,
]);

function assertWireInput(bytes: Uint8Array, label: string): void {
  if (bytes.length > MAX_WIRE_INPUT_BYTES) {
    throw new Error(`${label} exceeds ${MAX_WIRE_INPUT_BYTES}-byte input limit`);
  }
}

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertChunkJSONDomain(value: unknown, label: string): asserts value is ChunkJSON[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const indices = new Set<number>();
  for (const [position, chunk] of value.entries()) {
    assertRecord(chunk, `${label}[${position}]`);
    const index = assertBraidChunkIndex(chunk.index, `${label}[${position}].index`);
    if (indices.has(index)) throw new Error(`${label} contains duplicate chunk index ${index}`);
    indices.add(index);
  }
}

function assertEpoch(epoch: bigint): void {
  if (epoch < 0n || epoch > UINT64_MAX) {
    throw new Error('ML-KEM Braid epoch must be a uint64');
  }
}

function validateMessage(message: MLKEMBraidMessage): void {
  assertEpoch(message.epoch);
  if (!Number.isInteger(message.type) || MessageType[message.type] === undefined) {
    throw new Error(`Unknown ML-KEM Braid message type: ${String(message.type)}`);
  }
  const expectsChunk = CHUNK_MESSAGE_TYPES.has(message.type);
  if (expectsChunk) {
    assertBraidChunkIndex(message.chunkIndex, 'Chunk message index');
    if (message.data?.length !== PROTOCOL_CONSTANTS.CHUNK_SIZE) {
      throw new Error(`Chunk message requires exactly ${PROTOCOL_CONSTANTS.CHUNK_SIZE} data bytes`);
    }
  } else if (message.chunkIndex !== undefined || message.data !== undefined) {
    throw new Error('Header-only message cannot contain a chunk index or data');
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) {
    throw new Error('Hex string must use canonical lowercase byte encoding');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert uint64 to big-endian bytes
 */
export function uint64ToBytesBE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  const high = Number(value >> 32n);
  const low = Number(value & 0xffffffffn);
  bytes[0] = (high >>> 24) & 0xff;
  bytes[1] = (high >>> 16) & 0xff;
  bytes[2] = (high >>> 8) & 0xff;
  bytes[3] = high & 0xff;
  bytes[4] = (low >>> 24) & 0xff;
  bytes[5] = (low >>> 16) & 0xff;
  bytes[6] = (low >>> 8) & 0xff;
  bytes[7] = low & 0xff;
  return bytes;
}

/**
 * Convert big-endian bytes to uint64
 */
export function bytesToUint64BE(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new Error('Expected 8 bytes for uint64');
  }
  const high = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  const low = ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
  return (BigInt(high) << 32n) | BigInt(low);
}

/**
 * Convert uint16 to little-endian bytes
 */
export function uint16ToBytesLE(value: number): Uint8Array {
  assertBraidChunkIndex(value, 'uint16 value');
  const bytes = new Uint8Array(2);
  bytes[0] = value & 0xff;
  bytes[1] = (value >> 8) & 0xff;
  return bytes;
}

/**
 * Convert little-endian bytes to uint16
 */
export function bytesToUint16LE(bytes: Uint8Array): number {
  if (bytes.length < 2) {
    throw new Error('Expected at least 2 bytes for uint16');
  }
  return bytes[0] | (bytes[1] << 8);
}

/**
 * Get MessageType name from enum value
 */
export function getMessageTypeName(type: MessageType): string {
  return MessageType[type] || 'Unknown';
}

/**
 * Get MessageType value from name
 */
export function getMessageTypeValue(name: string): MessageType {
  const value = MessageType[name as keyof typeof MessageType];
  if (value === undefined) {
    throw new Error(`Unknown message type: ${name}`);
  }
  return value;
}

function assertV1VersionCapability(
  capability: { maxVersion?: unknown; minVersion?: unknown } | undefined
): void {
  if (!capability) {
    return;
  }

  if (capability.maxVersion !== 'v1' || capability.minVersion !== 'v1') {
    throw new Error('Unsupported ML-KEM Braid version capability: v1 is required');
  }
}

// =============================================================================
// Binary Format Serialization
// =============================================================================

/**
 * Binary shard format (Signal RS layer):
 * SHARD = INDEX (uint16_le) || DATA (32 bytes)
 */
export function serializeShardBinary(index: number, data: Uint8Array): Uint8Array {
  assertBraidChunkIndex(index, 'Shard index');
  if (data.length !== PROTOCOL_CONSTANTS.CHUNK_SIZE) {
    throw new Error(
      `Invalid chunk size: expected ${PROTOCOL_CONSTANTS.CHUNK_SIZE}, got ${data.length}`
    );
  }
  const result = new Uint8Array(2 + PROTOCOL_CONSTANTS.CHUNK_SIZE);
  result.set(uint16ToBytesLE(index), 0);
  result.set(data, 2);
  return result;
}

/**
 * Deserialize binary shard
 */
export function deserializeShardBinary(bytes: Uint8Array): {
  index: number;
  data: Uint8Array;
} {
  if (bytes.length !== 2 + PROTOCOL_CONSTANTS.CHUNK_SIZE) {
    throw new Error(
      `Invalid shard size: expected ${2 + PROTOCOL_CONSTANTS.CHUNK_SIZE}, got ${bytes.length}`
    );
  }
  return {
    index: bytesToUint16LE(bytes),
    data: bytes.slice(2),
  };
}

/**
 * Binary message format:
 * MESSAGE = EPOCH (uint64_be) || TYPE (uint8) || [INDEX (uint16_le) || DATA (32 bytes)]
 *
 * Header-only: 9 bytes
 * With chunk: 43 bytes
 */
export function serializeMessageBinary(msg: MLKEMBraidMessage): Uint8Array {
  validateMessage(msg);
  const hasData = msg.data !== undefined && msg.data.length > 0;
  const size = hasData ? 9 + 2 + PROTOCOL_CONSTANTS.CHUNK_SIZE : 9;

  const result = new Uint8Array(size);
  let offset = 0;

  // Epoch (uint64 big-endian)
  result.set(uint64ToBytesBE(msg.epoch), offset);
  offset += 8;

  // Type (uint8)
  result[offset++] = msg.type;

  // Optional: chunk index + data
  if (hasData) {
    result.set(uint16ToBytesLE(msg.chunkIndex ?? 0), offset);
    offset += 2;
    result.set(msg.data!, offset);
  }

  return result;
}

/**
 * Deserialize binary message
 */
export function deserializeMessageBinary(bytes: Uint8Array): MLKEMBraidMessage {
  assertWireInput(bytes, 'ML-KEM Braid binary message');
  if (bytes.length < 9) {
    throw new Error(`Invalid message size: minimum 9 bytes, got ${bytes.length}`);
  }

  const epoch = bytesToUint64BE(bytes.slice(0, 8));
  const type = bytes[8] as MessageType;

  const msg: MLKEMBraidMessage = { epoch, type };

  // Check for chunk data
  if (bytes.length === 9 + 2 + PROTOCOL_CONSTANTS.CHUNK_SIZE) {
    msg.chunkIndex = bytesToUint16LE(bytes.slice(9, 11));
    msg.data = bytes.slice(11);
  } else if (bytes.length !== 9) {
    throw new Error(`Invalid message size: expected 9 or 43 bytes, got ${bytes.length}`);
  }

  validateMessage(msg);
  return msg;
}

// =============================================================================
// Protobuf Format Serialization
// =============================================================================

// Lazy-loaded protobuf root
let protoRoot: protobuf.Root | null = null;
let V1MsgType: protobuf.Type | null = null;
let AuthenticatorType: protobuf.Type | null = null;
let PolynomialEncoderType: protobuf.Type | null = null;
let PolynomialDecoderType: protobuf.Type | null = null;

/**
 * Initialize protobuf types (loads .proto file)
 */
async function initProto(): Promise<void> {
  if (protoRoot) return;

  // Use protobufjs reflection API to define types inline
  // This avoids file system access which may not work in all environments
  protoRoot = new protobuf.Root();

  // Define Version enum (V_0 = 0, V_1 = 1)
  const Version = new protobuf.Enum('Version', {
    V_0: 0, // Reserved; runtime requires V_1
    V_1: 1, // ML-KEM Braid (post-quantum)
  });

  // Define Chunk message
  const Chunk = new protobuf.Type('Chunk')
    .add(new protobuf.Field('index', 1, 'uint32'))
    .add(new protobuf.Field('data', 2, 'bytes'));

  // Define ChunkEntry message
  const ChunkEntry = new protobuf.Type('ChunkEntry')
    .add(new protobuf.Field('index', 1, 'uint32'))
    .add(new protobuf.Field('data', 2, 'bytes'));

  // Define VersionCapability message (for negotiation)
  const VersionCapability = new protobuf.Type('VersionCapability')
    .add(new protobuf.Field('maxVersion', 1, 'Version'))
    .add(new protobuf.Field('minVersion', 2, 'Version'));

  // Define V1Msg message with oneof and optional version capability
  const V1Msg = new protobuf.Type('V1Msg')
    .add(new protobuf.Field('epoch', 1, 'uint64'))
    .add(new protobuf.Field('index', 2, 'uint32'))
    .add(
      new protobuf.OneOf('innerMsg')
        .add(new protobuf.Field('hdr', 3, 'Chunk'))
        .add(new protobuf.Field('ek', 4, 'Chunk'))
        .add(new protobuf.Field('ekCt1Ack', 5, 'Chunk'))
        .add(new protobuf.Field('ct1Ack', 6, 'bool'))
        .add(new protobuf.Field('ct1', 7, 'Chunk'))
        .add(new protobuf.Field('ct2', 8, 'Chunk'))
    )
    .add(new protobuf.Field('versionCapability', 9, 'VersionCapability'));

  // Define Authenticator message
  const Authenticator = new protobuf.Type('Authenticator')
    .add(new protobuf.Field('rootKey', 1, 'bytes'))
    .add(new protobuf.Field('macKey', 2, 'bytes'));

  // Define PolynomialEncoder message
  const PolynomialEncoder = new protobuf.Type('PolynomialEncoder')
    .add(new protobuf.Field('idx', 1, 'uint32'))
    .add(new protobuf.Field('pts', 2, 'bytes', 'repeated'))
    .add(new protobuf.Field('polys', 3, 'bytes', 'repeated'))
    .add(new protobuf.Field('messageSize', 4, 'uint32'));

  // Define PolynomialDecoder message
  const PolynomialDecoder = new protobuf.Type('PolynomialDecoder')
    .add(new protobuf.Field('ptsNeeded', 1, 'uint32'))
    .add(new protobuf.Field('polys', 2, 'uint32'))
    .add(new protobuf.Field('chunks', 3, 'ChunkEntry', 'repeated'))
    .add(new protobuf.Field('isComplete', 4, 'bool'))
    .add(new protobuf.Field('messageSize', 5, 'uint32'));

  // Add all types to root
  protoRoot.add(Version);
  protoRoot.add(Chunk);
  protoRoot.add(ChunkEntry);
  protoRoot.add(VersionCapability);
  protoRoot.add(V1Msg);
  protoRoot.add(Authenticator);
  protoRoot.add(PolynomialEncoder);
  protoRoot.add(PolynomialDecoder);

  // Resolve nested type references
  V1MsgType = protoRoot.lookupType('V1Msg');
  AuthenticatorType = protoRoot.lookupType('Authenticator');
  PolynomialEncoderType = protoRoot.lookupType('PolynomialEncoder');
  PolynomialDecoderType = protoRoot.lookupType('PolynomialDecoder');
}

/**
 * Serialize a message with the ML-KEM Braid protobuf schema.
 */
export async function serializeMessageProto(msg: MLKEMBraidMessage): Promise<Uint8Array> {
  validateMessage(msg);
  await initProto();

  // Protobuf uses Number for uint64 (safe up to 2^53-1)
  // For larger values, we'd need to use protobufjs's Long type
  let epochValue: number | object = Number(msg.epoch);
  if (msg.epoch > BigInt(Number.MAX_SAFE_INTEGER)) {
    // Use Long from protobufjs for large values
    const Long = protobuf.util.Long;
    if (Long) {
      const high = Number(msg.epoch >> 32n);
      const low = Number(msg.epoch & 0xffffffffn);
      epochValue = new Long(low, high, true);
    }
  }

  const protoMsg: Record<string, unknown> = {
    epoch: epochValue,
    index: msg.chunkIndex ?? 0,
  };

  // Map MessageType to oneof field
  if (msg.data) {
    const chunk = { index: msg.chunkIndex ?? 0, data: msg.data };
    switch (msg.type) {
      case MessageType.Hdr:
        protoMsg.hdr = chunk;
        break;
      case MessageType.Ek:
        protoMsg.ek = chunk;
        break;
      case MessageType.EkCt1Ack:
        protoMsg.ekCt1Ack = chunk;
        break;
      case MessageType.Ct1:
        protoMsg.ct1 = chunk;
        break;
      case MessageType.Ct2:
        protoMsg.ct2 = chunk;
        break;
      default:
        // None type - no chunk data in oneof
        break;
    }
  } else if (msg.type === MessageType.Ct1Ack) {
    protoMsg.ct1Ack = true;
  }

  // Add version capability if present (during negotiation)
  if (msg.versionCapability) {
    assertV1VersionCapability(msg.versionCapability);
    protoMsg.versionCapability = {
      maxVersion: 1,
      minVersion: 1,
    };
  }

  const errMsg = V1MsgType!.verify(protoMsg);
  if (errMsg) {
    throw new Error(`Invalid message: ${errMsg}`);
  }

  const message = V1MsgType!.create(protoMsg);
  return V1MsgType!.encode(message).finish();
}

/**
 * Deserialize protobuf message
 */
export async function deserializeMessageProto(bytes: Uint8Array): Promise<MLKEMBraidMessage> {
  assertWireInput(bytes, 'ML-KEM Braid protobuf message');
  await initProto();

  const decoded = V1MsgType!.decode(bytes);
  const obj = V1MsgType!.toObject(decoded, {
    longs: String, // bigint support
    bytes: Uint8Array,
  });

  const epoch = typeof obj.epoch === 'string' ? BigInt(obj.epoch) : BigInt(obj.epoch || 0);
  let type = MessageType.None;
  let chunkIndex: number | undefined;
  let data: Uint8Array | undefined;

  // Determine type from oneof
  if (obj.hdr) {
    type = MessageType.Hdr;
    chunkIndex = obj.hdr.index;
    data = obj.hdr.data;
  } else if (obj.ek) {
    type = MessageType.Ek;
    chunkIndex = obj.ek.index;
    data = obj.ek.data;
  } else if (obj.ekCt1Ack) {
    type = MessageType.EkCt1Ack;
    chunkIndex = obj.ekCt1Ack.index;
    data = obj.ekCt1Ack.data;
  } else if (obj.ct1Ack !== undefined) {
    type = MessageType.Ct1Ack;
  } else if (obj.ct1) {
    type = MessageType.Ct1;
    chunkIndex = obj.ct1.index;
    data = obj.ct1.data;
  } else if (obj.ct2) {
    type = MessageType.Ct2;
    chunkIndex = obj.ct2.index;
    data = obj.ct2.data;
  }

  const msg: MLKEMBraidMessage = { epoch, type };
  if (chunkIndex !== undefined) msg.chunkIndex = chunkIndex;
  if (data) msg.data = data;

  // Extract version capability if present
  if (obj.versionCapability) {
    if (obj.versionCapability.maxVersion !== 1 || obj.versionCapability.minVersion !== 1) {
      throw new Error('Unsupported ML-KEM Braid version capability: v1 is required');
    }
    msg.versionCapability = {
      maxVersion: 'v1',
      minVersion: 'v1',
    };
  }

  validateMessage(msg);
  return msg;
}

/**
 * Serialize authenticator state to protobuf
 */
export async function serializeAuthenticatorProto(auth: AuthenticatorState): Promise<Uint8Array> {
  await initProto();

  const protoMsg = {
    rootKey: auth.root_key,
    macKey: auth.mac_key,
  };

  const errMsg = AuthenticatorType!.verify(protoMsg);
  if (errMsg) {
    throw new Error(`Invalid authenticator: ${errMsg}`);
  }

  const message = AuthenticatorType!.create(protoMsg);
  return AuthenticatorType!.encode(message).finish();
}

/**
 * Deserialize protobuf authenticator state
 */
export async function deserializeAuthenticatorProto(
  bytes: Uint8Array
): Promise<AuthenticatorState> {
  assertWireInput(bytes, 'ML-KEM Braid authenticator protobuf');
  await initProto();

  const decoded = AuthenticatorType!.decode(bytes);
  const obj = AuthenticatorType!.toObject(decoded, { bytes: Uint8Array });

  const result = {
    root_key: obj.rootKey,
    mac_key: obj.macKey,
  };
  if (result.root_key?.length !== 32 || result.mac_key?.length !== 32) {
    throw new Error('Authenticator keys must each contain exactly 32 bytes');
  }
  return result;
}

// =============================================================================
// JSON Format Serialization
// =============================================================================

/**
 * Serialize message to JSON
 */
export function serializeMessageJSON(msg: MLKEMBraidMessage): string {
  validateMessage(msg);
  const json: MLKEMBraidMessageJSON = {
    epoch: msg.epoch.toString(),
    type: getMessageTypeName(msg.type),
  };

  if (msg.chunkIndex !== undefined) {
    json.index = msg.chunkIndex;
  }

  if (msg.data) {
    json.data = bytesToHex(msg.data);
  }

  if (msg.versionCapability) {
    assertV1VersionCapability(msg.versionCapability);
    json.versionCapability = {
      maxVersion: msg.versionCapability.maxVersion,
      minVersion: msg.versionCapability.minVersion,
    };
  }

  return JSON.stringify(json);
}

/**
 * Deserialize JSON message
 */
export function deserializeMessageJSON(jsonStr: string): MLKEMBraidMessage {
  assertWireInput(new TextEncoder().encode(jsonStr), 'ML-KEM Braid JSON message');
  const parsed: unknown = JSON.parse(jsonStr);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('ML-KEM Braid JSON message must be an object');
  }
  const json = parsed as MLKEMBraidMessageJSON;
  if (typeof json.epoch !== 'string' || !/^(?:0|[1-9]\d*)$/.test(json.epoch)) {
    throw new Error('ML-KEM Braid epoch must use canonical unsigned decimal encoding');
  }
  if (typeof json.type !== 'string') {
    throw new Error('ML-KEM Braid message type must be a string');
  }

  const msg: MLKEMBraidMessage = {
    epoch: BigInt(json.epoch),
    type: getMessageTypeValue(json.type),
  };

  if (json.index !== undefined) {
    msg.chunkIndex = json.index;
  }

  if (json.data) {
    msg.data = hexToBytes(json.data);
  }

  if (json.versionCapability) {
    assertV1VersionCapability(json.versionCapability);
    msg.versionCapability = {
      maxVersion: json.versionCapability.maxVersion,
      minVersion: json.versionCapability.minVersion,
    };
  }

  validateMessage(msg);
  return msg;
}

/**
 * Serialize authenticator state to JSON
 */
export function serializeAuthenticatorJSON(auth: AuthenticatorState): string {
  const json: AuthenticatorJSON = {
    root_key: bytesToHex(auth.root_key),
    mac_key: bytesToHex(auth.mac_key),
  };
  return JSON.stringify(json);
}

/**
 * Deserialize JSON authenticator state
 */
export function deserializeAuthenticatorJSON(jsonStr: string): AuthenticatorState {
  assertWireInput(new TextEncoder().encode(jsonStr), 'ML-KEM Braid authenticator JSON');
  const json: AuthenticatorJSON = JSON.parse(jsonStr);
  const result = {
    root_key: hexToBytes(json.root_key),
    mac_key: hexToBytes(json.mac_key),
  };
  if (result.root_key.length !== 32 || result.mac_key.length !== 32) {
    throw new Error('Authenticator keys must each contain exactly 32 bytes');
  }
  return result;
}

// =============================================================================
// Encoder/Decoder Serialization (JSON)
// =============================================================================

/**
 * Serialize encoder state to JSON
 */
export function serializeEncoderJSON(state: {
  currentChunkIndex: number;
  dataChunks: Uint8Array[];
  polynomials: Array<{ coefficients: number[] }>;
  originalDataSize: number;
}): string {
  assertBraidEncoderCursor(state.currentChunkIndex, 'Encoder state index');
  const json: PolyEncoderJSON = {
    idx: state.currentChunkIndex,
    pts: state.dataChunks.map(bytesToHex),
    polys: state.polynomials.map((p) =>
      bytesToHex(new Uint8Array(p.coefficients.flatMap((c) => [(c >> 8) & 0xff, c & 0xff])))
    ),
    messageSize: state.originalDataSize,
  };
  return JSON.stringify(json);
}

/**
 * Deserialize JSON encoder state
 */
export function deserializeEncoderJSON(jsonStr: string): PolyEncoderJSON {
  assertWireInput(new TextEncoder().encode(jsonStr), 'ML-KEM Braid encoder JSON state');
  const parsed: unknown = JSON.parse(jsonStr);
  assertRecord(parsed, 'ML-KEM Braid encoder JSON state');
  assertBraidEncoderCursor(parsed.idx, 'Encoder state index');
  return parsed as unknown as PolyEncoderJSON;
}

/**
 * Serialize decoder state to JSON
 */
export function serializeDecoderJSON(state: {
  config: { dataChunks: number };
  receivedChunks: Map<number, Uint8Array>;
  messageSize: number;
}): string {
  const chunks: ChunkJSON[] = [];
  for (const [index, data] of state.receivedChunks) {
    assertBraidChunkIndex(index, 'Decoder chunk index');
    chunks.push({ index, data: bytesToHex(data) });
  }

  const json: PolyDecoderJSON = {
    ptsNeeded: state.config.dataChunks,
    polys: 16,
    chunks,
    isComplete: state.receivedChunks.size >= state.config.dataChunks,
    messageSize: state.messageSize,
  };
  return JSON.stringify(json);
}

/**
 * Deserialize JSON decoder state
 */
export function deserializeDecoderJSON(jsonStr: string): PolyDecoderJSON {
  assertWireInput(new TextEncoder().encode(jsonStr), 'ML-KEM Braid decoder JSON state');
  const parsed: unknown = JSON.parse(jsonStr);
  assertRecord(parsed, 'ML-KEM Braid decoder JSON state');
  assertChunkJSONDomain(parsed.chunks, 'Decoder state chunks');
  return parsed as unknown as PolyDecoderJSON;
}

// =============================================================================
// Encoder/Decoder Serialization (Protobuf)
// =============================================================================

/**
 * Serialize encoder state to protobuf
 */
export async function serializeEncoderProto(state: {
  currentChunkIndex: number;
  dataChunks: Uint8Array[];
  polynomials: Array<{ coefficients: number[] }>;
  originalDataSize: number;
}): Promise<Uint8Array> {
  assertBraidEncoderCursor(state.currentChunkIndex, 'Encoder state index');
  await initProto();

  const protoMsg = {
    idx: state.currentChunkIndex,
    pts: state.dataChunks,
    polys: state.polynomials.map(
      (p) => new Uint8Array(p.coefficients.flatMap((c) => [(c >> 8) & 0xff, c & 0xff]))
    ),
    messageSize: state.originalDataSize,
  };

  const errMsg = PolynomialEncoderType!.verify(protoMsg);
  if (errMsg) {
    throw new Error(`Invalid encoder state: ${errMsg}`);
  }

  const message = PolynomialEncoderType!.create(protoMsg);
  return PolynomialEncoderType!.encode(message).finish();
}

/**
 * Deserialize protobuf encoder state
 */
export async function deserializeEncoderProto(bytes: Uint8Array): Promise<{
  idx: number;
  pts: Uint8Array[];
  polys: number[][];
  messageSize: number;
}> {
  assertWireInput(bytes, 'ML-KEM Braid encoder protobuf state');
  await initProto();

  const decoded = PolynomialEncoderType!.decode(bytes);
  const obj = PolynomialEncoderType!.toObject(decoded, { bytes: Uint8Array });

  // Convert polys back to coefficient arrays
  const polys = (obj.polys || []).map((polyBytes: Uint8Array) => {
    const coeffs: number[] = [];
    for (let i = 0; i < polyBytes.length; i += 2) {
      coeffs.push((polyBytes[i] << 8) | polyBytes[i + 1]);
    }
    return coeffs;
  });

  const idx = obj.idx || 0;
  assertBraidEncoderCursor(idx, 'Encoder state index');
  return {
    idx,
    pts: obj.pts || [],
    polys,
    messageSize: obj.messageSize || 0,
  };
}

/**
 * Serialize decoder state to protobuf
 */
export async function serializeDecoderProto(state: {
  config: { dataChunks: number };
  receivedChunks: Map<number, Uint8Array>;
  messageSize: number;
}): Promise<Uint8Array> {
  await initProto();

  const chunks: Array<{ index: number; data: Uint8Array }> = [];
  for (const [index, data] of state.receivedChunks) {
    assertBraidChunkIndex(index, 'Decoder chunk index');
    chunks.push({ index, data });
  }

  const protoMsg = {
    ptsNeeded: state.config.dataChunks,
    polys: 16,
    chunks,
    isComplete: state.receivedChunks.size >= state.config.dataChunks,
    messageSize: state.messageSize,
  };

  const errMsg = PolynomialDecoderType!.verify(protoMsg);
  if (errMsg) {
    throw new Error(`Invalid decoder state: ${errMsg}`);
  }

  const message = PolynomialDecoderType!.create(protoMsg);
  return PolynomialDecoderType!.encode(message).finish();
}

/**
 * Deserialize protobuf decoder state
 */
export async function deserializeDecoderProto(bytes: Uint8Array): Promise<{
  ptsNeeded: number;
  polys: number;
  chunks: Map<number, Uint8Array>;
  isComplete: boolean;
  messageSize: number;
}> {
  assertWireInput(bytes, 'ML-KEM Braid decoder protobuf state');
  await initProto();

  const decoded = PolynomialDecoderType!.decode(bytes);
  const obj = PolynomialDecoderType!.toObject(decoded, { bytes: Uint8Array });

  const chunks = new Map<number, Uint8Array>();
  for (const chunk of obj.chunks || []) {
    const index = assertBraidChunkIndex(chunk.index, 'Decoder chunk index');
    if (chunks.has(index)) {
      throw new Error(`Decoder state contains duplicate chunk index ${index}`);
    }
    chunks.set(index, chunk.data);
  }

  return {
    ptsNeeded: obj.ptsNeeded || 0,
    polys: obj.polys || 16,
    chunks,
    isComplete: obj.isComplete || false,
    messageSize: obj.messageSize || 0,
  };
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize serialization module (loads protobuf)
 */
export async function initSerialization(): Promise<void> {
  await initProto();
}

/**
 * Check if serialization is ready
 */
export function isSerializationReady(): boolean {
  return protoRoot !== null;
}
