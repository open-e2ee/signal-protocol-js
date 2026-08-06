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

import {
  ProtoReader,
  concatFields,
  encodeBoolField,
  encodeBytesField,
  encodeEnumField,
  encodeMessageField,
  encodeRepeatedBytesField,
  encodeRepeatedMessageField,
  encodeUint32Field,
  encodeUint64Field,
} from '../../../encoding/proto/primitives';
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
 * Binary shard format (ML-KEM Braid RS layer):
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

/**
 * Field numbers from `proto/pq_ratchet.proto`. They are frozen: the same wire
 * is read by the reference implementation, and `Authenticator`,
 * `PolynomialEncoder`, and `PolynomialDecoder` are the persisted ratchet
 * state, so an installed client must keep decoding what it wrote yesterday.
 */
const V1MSG_FIELDS = {
  epoch: 1,
  index: 2,
  hdr: 3,
  ek: 4,
  ekCt1Ack: 5,
  ct1Ack: 6,
  ct1: 7,
  ct2: 8,
  versionCapability: 9,
} as const;

const CHUNK_FIELDS = { index: 1, data: 2 } as const;

const VERSION_CAPABILITY_FIELDS = { maxVersion: 1, minVersion: 2 } as const;

const AUTHENTICATOR_FIELDS = { rootKey: 1, macKey: 2 } as const;

const POLYNOMIAL_ENCODER_FIELDS = { idx: 1, pts: 2, polys: 3, messageSize: 4 } as const;

const POLYNOMIAL_DECODER_FIELDS = {
  ptsNeeded: 1,
  polys: 2,
  chunks: 3,
  isComplete: 4,
  messageSize: 5,
} as const;

/** `Version.V_1`; `V_0 = 0` is reserved and the runtime never emits it. */
const VERSION_V1 = 1;

/**
 * The `V1Msg.inner_msg` oneof, in field order. Setting one arm clears the
 * others, on encode and on decode alike: a message that arrives carrying two
 * arms keeps only the last one on the wire.
 */
const V1MSG_ONEOF_ARMS = ['hdr', 'ek', 'ekCt1Ack', 'ct1Ack', 'ct1', 'ct2'] as const;

/**
 * Wire-level view of a decoded message: every field is optional and is present
 * only when the bytes carried it.
 *
 * Presence is the contract, not the value. A field explicitly set to its zero
 * value is written to the wire — `epoch: 0` is `08 00`, `isComplete: false` is
 * `20 00` — and an absent field decodes to `undefined` here so the public
 * functions below can apply their own defaults. Collapsing the two would
 * change the bytes for messages this package has already persisted.
 */
interface ChunkWire {
  index?: number;
  data?: Uint8Array;
}

interface VersionCapabilityWire {
  maxVersion?: number;
  minVersion?: number;
}

interface V1MsgWire {
  epoch?: bigint;
  index?: number;
  hdr?: ChunkWire;
  ek?: ChunkWire;
  ekCt1Ack?: ChunkWire;
  ct1Ack?: boolean;
  ct1?: ChunkWire;
  ct2?: ChunkWire;
  versionCapability?: VersionCapabilityWire;
}

interface AuthenticatorWire {
  rootKey?: Uint8Array;
  macKey?: Uint8Array;
}

interface PolynomialEncoderWire {
  idx?: number;
  pts: Uint8Array[];
  polys: Uint8Array[];
  messageSize?: number;
}

interface PolynomialDecoderWire {
  ptsNeeded?: number;
  polys?: number;
  chunks: ChunkWire[];
  isComplete?: boolean;
  messageSize?: number;
}

function assertProtoBytes(value: unknown, label: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array`);
  }
}

function assertProtoUint32(value: unknown, label: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffffffff) {
    throw new Error(`${label} must be an integer between 0 and 4294967295`);
  }
}

/** Assign one oneof arm, clearing whichever sibling was set before. */
function setInnerMsg<K extends (typeof V1MSG_ONEOF_ARMS)[number]>(
  msg: V1MsgWire,
  arm: K,
  value: V1MsgWire[K]
): void {
  for (const other of V1MSG_ONEOF_ARMS) {
    delete msg[other];
  }
  msg[arm] = value;
}

function encodeChunk(chunk: ChunkWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (chunk.index !== undefined) {
    fields.push(encodeUint32Field(CHUNK_FIELDS.index, chunk.index));
  }
  if (chunk.data !== undefined) {
    fields.push(encodeBytesField(CHUNK_FIELDS.data, chunk.data));
  }
  return concatFields(...fields);
}

function decodeChunk(bytes: Uint8Array): ChunkWire {
  const chunk: ChunkWire = {};
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case CHUNK_FIELDS.index:
        chunk.index = reader.readUint32();
        break;
      case CHUNK_FIELDS.data:
        chunk.data = reader.readBytes();
        break;
      default:
        reader.skipField();
    }
  }

  return chunk;
}

function encodeVersionCapability(capability: VersionCapabilityWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (capability.maxVersion !== undefined) {
    fields.push(encodeEnumField(VERSION_CAPABILITY_FIELDS.maxVersion, capability.maxVersion));
  }
  if (capability.minVersion !== undefined) {
    fields.push(encodeEnumField(VERSION_CAPABILITY_FIELDS.minVersion, capability.minVersion));
  }
  return concatFields(...fields);
}

function decodeVersionCapability(bytes: Uint8Array): VersionCapabilityWire {
  const capability: VersionCapabilityWire = {};
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case VERSION_CAPABILITY_FIELDS.maxVersion:
        capability.maxVersion = reader.readEnum();
        break;
      case VERSION_CAPABILITY_FIELDS.minVersion:
        capability.minVersion = reader.readEnum();
        break;
      default:
        reader.skipField();
    }
  }

  return capability;
}

function encodeV1Msg(msg: V1MsgWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (msg.epoch !== undefined) {
    fields.push(encodeUint64Field(V1MSG_FIELDS.epoch, msg.epoch));
  }
  if (msg.index !== undefined) {
    fields.push(encodeUint32Field(V1MSG_FIELDS.index, msg.index));
  }
  if (msg.hdr !== undefined) {
    fields.push(encodeMessageField(V1MSG_FIELDS.hdr, encodeChunk(msg.hdr)));
  }
  if (msg.ek !== undefined) {
    fields.push(encodeMessageField(V1MSG_FIELDS.ek, encodeChunk(msg.ek)));
  }
  if (msg.ekCt1Ack !== undefined) {
    fields.push(encodeMessageField(V1MSG_FIELDS.ekCt1Ack, encodeChunk(msg.ekCt1Ack)));
  }
  if (msg.ct1Ack !== undefined) {
    fields.push(encodeBoolField(V1MSG_FIELDS.ct1Ack, msg.ct1Ack));
  }
  if (msg.ct1 !== undefined) {
    fields.push(encodeMessageField(V1MSG_FIELDS.ct1, encodeChunk(msg.ct1)));
  }
  if (msg.ct2 !== undefined) {
    fields.push(encodeMessageField(V1MSG_FIELDS.ct2, encodeChunk(msg.ct2)));
  }
  if (msg.versionCapability !== undefined) {
    fields.push(
      encodeMessageField(
        V1MSG_FIELDS.versionCapability,
        encodeVersionCapability(msg.versionCapability)
      )
    );
  }
  return concatFields(...fields);
}

function decodeV1Msg(bytes: Uint8Array): V1MsgWire {
  const msg: V1MsgWire = {};
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case V1MSG_FIELDS.epoch:
        msg.epoch = reader.readUint64();
        break;
      case V1MSG_FIELDS.index:
        msg.index = reader.readUint32();
        break;
      case V1MSG_FIELDS.hdr:
        setInnerMsg(msg, 'hdr', decodeChunk(reader.readMessage()));
        break;
      case V1MSG_FIELDS.ek:
        setInnerMsg(msg, 'ek', decodeChunk(reader.readMessage()));
        break;
      case V1MSG_FIELDS.ekCt1Ack:
        setInnerMsg(msg, 'ekCt1Ack', decodeChunk(reader.readMessage()));
        break;
      case V1MSG_FIELDS.ct1Ack:
        setInnerMsg(msg, 'ct1Ack', reader.readBool());
        break;
      case V1MSG_FIELDS.ct1:
        setInnerMsg(msg, 'ct1', decodeChunk(reader.readMessage()));
        break;
      case V1MSG_FIELDS.ct2:
        setInnerMsg(msg, 'ct2', decodeChunk(reader.readMessage()));
        break;
      case V1MSG_FIELDS.versionCapability:
        msg.versionCapability = decodeVersionCapability(reader.readMessage());
        break;
      default:
        reader.skipField();
    }
  }

  return msg;
}

function encodeAuthenticator(auth: AuthenticatorWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (auth.rootKey !== undefined) {
    fields.push(encodeBytesField(AUTHENTICATOR_FIELDS.rootKey, auth.rootKey));
  }
  if (auth.macKey !== undefined) {
    fields.push(encodeBytesField(AUTHENTICATOR_FIELDS.macKey, auth.macKey));
  }
  return concatFields(...fields);
}

function decodeAuthenticator(bytes: Uint8Array): AuthenticatorWire {
  const auth: AuthenticatorWire = {};
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case AUTHENTICATOR_FIELDS.rootKey:
        auth.rootKey = reader.readBytes();
        break;
      case AUTHENTICATOR_FIELDS.macKey:
        auth.macKey = reader.readBytes();
        break;
      default:
        reader.skipField();
    }
  }

  return auth;
}

function encodePolynomialEncoder(state: PolynomialEncoderWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (state.idx !== undefined) {
    fields.push(encodeUint32Field(POLYNOMIAL_ENCODER_FIELDS.idx, state.idx));
  }
  fields.push(encodeRepeatedBytesField(POLYNOMIAL_ENCODER_FIELDS.pts, state.pts));
  fields.push(encodeRepeatedBytesField(POLYNOMIAL_ENCODER_FIELDS.polys, state.polys));
  if (state.messageSize !== undefined) {
    fields.push(encodeUint32Field(POLYNOMIAL_ENCODER_FIELDS.messageSize, state.messageSize));
  }
  return concatFields(...fields);
}

function decodePolynomialEncoder(bytes: Uint8Array): PolynomialEncoderWire {
  const state: PolynomialEncoderWire = { pts: [], polys: [] };
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case POLYNOMIAL_ENCODER_FIELDS.idx:
        state.idx = reader.readUint32();
        break;
      case POLYNOMIAL_ENCODER_FIELDS.pts:
        state.pts.push(reader.readBytes());
        break;
      case POLYNOMIAL_ENCODER_FIELDS.polys:
        state.polys.push(reader.readBytes());
        break;
      case POLYNOMIAL_ENCODER_FIELDS.messageSize:
        state.messageSize = reader.readUint32();
        break;
      default:
        reader.skipField();
    }
  }

  return state;
}

function encodePolynomialDecoder(state: PolynomialDecoderWire): Uint8Array {
  const fields: Uint8Array[] = [];
  if (state.ptsNeeded !== undefined) {
    fields.push(encodeUint32Field(POLYNOMIAL_DECODER_FIELDS.ptsNeeded, state.ptsNeeded));
  }
  if (state.polys !== undefined) {
    fields.push(encodeUint32Field(POLYNOMIAL_DECODER_FIELDS.polys, state.polys));
  }
  fields.push(
    encodeRepeatedMessageField(POLYNOMIAL_DECODER_FIELDS.chunks, state.chunks.map(encodeChunk))
  );
  if (state.isComplete !== undefined) {
    fields.push(encodeBoolField(POLYNOMIAL_DECODER_FIELDS.isComplete, state.isComplete));
  }
  if (state.messageSize !== undefined) {
    fields.push(encodeUint32Field(POLYNOMIAL_DECODER_FIELDS.messageSize, state.messageSize));
  }
  return concatFields(...fields);
}

function decodePolynomialDecoder(bytes: Uint8Array): PolynomialDecoderWire {
  const state: PolynomialDecoderWire = { chunks: [] };
  const reader = new ProtoReader(bytes);

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case POLYNOMIAL_DECODER_FIELDS.ptsNeeded:
        state.ptsNeeded = reader.readUint32();
        break;
      case POLYNOMIAL_DECODER_FIELDS.polys:
        state.polys = reader.readUint32();
        break;
      case POLYNOMIAL_DECODER_FIELDS.chunks:
        state.chunks.push(decodeChunk(reader.readMessage()));
        break;
      case POLYNOMIAL_DECODER_FIELDS.isComplete:
        state.isComplete = reader.readBool();
        break;
      case POLYNOMIAL_DECODER_FIELDS.messageSize:
        state.messageSize = reader.readUint32();
        break;
      default:
        reader.skipField();
    }
  }

  return state;
}

/**
 * Serialize a message with the ML-KEM Braid protobuf schema.
 */
export async function serializeMessageProto(msg: MLKEMBraidMessage): Promise<Uint8Array> {
  validateMessage(msg);

  // Both scalars are written even at zero: the epoch and the chunk index are
  // always set on the wire, never elided as proto3 defaults.
  const protoMsg: V1MsgWire = {
    epoch: msg.epoch,
    index: msg.chunkIndex ?? 0,
  };

  // Map MessageType to oneof field
  if (msg.data) {
    const chunk: ChunkWire = { index: msg.chunkIndex ?? 0, data: msg.data };
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
      maxVersion: VERSION_V1,
      minVersion: VERSION_V1,
    };
  }

  return encodeV1Msg(protoMsg);
}

/**
 * Deserialize protobuf message
 */
export async function deserializeMessageProto(bytes: Uint8Array): Promise<MLKEMBraidMessage> {
  assertWireInput(bytes, 'ML-KEM Braid protobuf message');

  const obj = decodeV1Msg(bytes);

  const epoch = obj.epoch ?? 0n;
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
  assertProtoBytes(auth.root_key, 'Authenticator root key');
  assertProtoBytes(auth.mac_key, 'Authenticator MAC key');

  return encodeAuthenticator({
    rootKey: auth.root_key,
    macKey: auth.mac_key,
  });
}

/**
 * Deserialize protobuf authenticator state
 */
export async function deserializeAuthenticatorProto(
  bytes: Uint8Array
): Promise<AuthenticatorState> {
  assertWireInput(bytes, 'ML-KEM Braid authenticator protobuf');

  const { rootKey, macKey } = decodeAuthenticator(bytes);

  if (rootKey?.length !== 32 || macKey?.length !== 32) {
    throw new Error('Authenticator keys must each contain exactly 32 bytes');
  }
  return {
    root_key: rootKey,
    mac_key: macKey,
  };
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
  assertProtoUint32(state.originalDataSize, 'Encoder state message size');
  for (const [position, chunk] of state.dataChunks.entries()) {
    assertProtoBytes(chunk, `Encoder state evaluation point ${position}`);
  }

  return encodePolynomialEncoder({
    idx: state.currentChunkIndex,
    pts: state.dataChunks,
    polys: state.polynomials.map(
      (p) => new Uint8Array(p.coefficients.flatMap((c) => [(c >> 8) & 0xff, c & 0xff]))
    ),
    messageSize: state.originalDataSize,
  });
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

  const obj = decodePolynomialEncoder(bytes);

  // Convert polys back to coefficient arrays
  const polys = obj.polys.map((polyBytes: Uint8Array) => {
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
  const chunks: ChunkWire[] = [];
  for (const [index, data] of state.receivedChunks) {
    assertBraidChunkIndex(index, 'Decoder chunk index');
    assertProtoBytes(data, `Decoder chunk ${index} data`);
    chunks.push({ index, data });
  }

  assertProtoUint32(state.config.dataChunks, 'Decoder state points needed');
  assertProtoUint32(state.messageSize, 'Decoder state message size');

  return encodePolynomialDecoder({
    ptsNeeded: state.config.dataChunks,
    polys: 16,
    chunks,
    isComplete: state.receivedChunks.size >= state.config.dataChunks,
    messageSize: state.messageSize,
  });
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

  const obj = decodePolynomialDecoder(bytes);

  const chunks = new Map<number, Uint8Array>();
  for (const chunk of obj.chunks) {
    const index = assertBraidChunkIndex(chunk.index, 'Decoder chunk index');
    if (chunks.has(index)) {
      throw new Error(`Decoder state contains duplicate chunk index ${index}`);
    }
    // A chunk entry with no data field at all is malformed state. The
    // reflection codec used to admit it and put `undefined` in the map, which
    // surfaced as a failure inside the Reed-Solomon decoder instead of here.
    if (chunk.data === undefined) {
      throw new Error(`Decoder state chunk ${index} is missing its data`);
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
 * Initialize serialization module.
 *
 * Nothing is loaded any more — the codecs above are static functions, so there
 * is no schema to build at runtime and no first-call latency to pay. Kept, and
 * kept async, because callers await it before serializing.
 */
export async function initSerialization(): Promise<void> {
  return Promise.resolve();
}

/**
 * Check if serialization is ready
 *
 * Always true: with static codecs there is no state that could be missing.
 */
export function isSerializationReady(): boolean {
  return true;
}
