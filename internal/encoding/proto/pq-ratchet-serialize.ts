/**
 * SPQR Wire Format — profile binary serialization
 *
 * Uses the compact SPQR binary format. Raw SPQR bytes are stored directly in the
 * pq_ratchet field (field 5)
 * of SignalMessage — no protobuf envelope.
 *
 * `SPQR` V1 format:
 *   VERSION(1) | VARINT(epoch) | VARINT(chain_index) | MSG_TYPE(1) | [VARINT(chunk_index) | CHUNK_DATA(32)]
 *   Chunks are required for Hdr, Ek, EkCt1Ack, Ct1, and Ct2. None and Ct1Ack
 *   are header-only, with trailing data allowed for future protocol upgrades.
 *
 * Mode byte values (MSG_TYPE):
 *   0x00 = None (header-only, no PQ data for this message)
 *   0x01-0x06 = Braid message types (Hdr through Ct2)
 *   0x80 = Direct mode: ML-KEM-768 ciphertext follows
 *   0x81 = Direct mode: ML-KEM-768 public key follows
 *   0x82 = Direct mode: ML-KEM-768 ciphertext + public key both follow
 *
 * Version byte:
 *   0x01 = V1 (SPQR active)
 *
 * Version negotiation is implicit in byte 0 — replaces the JSON
 * versionCapability field that added 30-50 bytes per message.
 *
 * @internal
 */

import { assertBraidChunkIndex } from '../../protocol/spqr/ml-kem-braid/chunk-domain';

// ============================================================================
// Constants
// ============================================================================

/** SPQR V1 version byte */
export {};
const VERSION_V1 = 0x01;

/** Direct mode: ML-KEM-768 ciphertext only */
const DIRECT_CIPHERTEXT = 0x80;
/** Direct mode: ML-KEM-768 public key only */
const DIRECT_PUBLIC_KEY = 0x81;
/** Direct mode: both ML-KEM-768 ciphertext and public key */
const DIRECT_BOTH = 0x82;
/** None: no braid/direct payload (header-only message with epoch/index) */
const MODE_NONE = 0x00;

/** ML-KEM-768 ciphertext size */
const MLKEM768_CIPHERTEXT_SIZE = 1088;
/** ML-KEM-768 public key size */
const MLKEM768_PUBLIC_KEY_SIZE = 1184;
/** Braid chunk data size */
const BRAID_CHUNK_SIZE = 32;
const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_SAFE_INTEGER_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_VARINT_U64_BYTES = 10;

/**
 * Valid braid message types (`SPQR` MessageType enum, values 1-6).
 */
const MAX_BRAID_MSG_TYPE = 6;
const BRAID_CT1_ACK_MSG_TYPE = 4;

// ============================================================================
// Types
// ============================================================================

export type SPQRWireEpoch = number | bigint;

/**
 * Decoded SPQR wire message.
 *
 * Represents the content of SignalMessage field 5 (pq_ratchet) after
 * decoding from the compact binary format.
 */
export interface SPQRWireMessage {
  /** Protocol version: V1 SPQR active */
  version: 1;
  /** SPQR wire epoch (one-based; may use u64-width values in braid mode) */
  epoch?: SPQRWireEpoch;
  /** Message index within epoch (varint-encoded, replaces messageNumber) */
  chainIndex?: number;
  /** Payload mode */
  mode: 'none' | 'braid' | 'direct';

  // Braid mode fields
  /** `SPQR` MessageType enum value (0x01-0x06: Hdr..Ct2) */
  braidMsgType?: number;
  /** Chunk evaluation point index (varint-encoded, the reference decoder accepts uint16 range) */
  braidChunkIndex?: number;
  /** Chunk data (32 bytes) */
  braidChunkData?: Uint8Array;

  // Direct mode fields
  /** ML-KEM-768 ciphertext (1,088 bytes) */
  kyberCiphertext?: Uint8Array;
  /** ML-KEM-768 public key (1,184 bytes) */
  kyberPublicKey?: Uint8Array;
}

// ============================================================================
// Varint encoding (LEB128 — matches the SPQR wire format)
// ============================================================================

function assertUint64(name: string, value: SPQRWireEpoch, min: bigint = 0n): bigint {
  const bigintValue =
    typeof value === 'bigint'
      ? value
      : Number.isInteger(value)
        ? BigInt(value)
        : (() => {
            throw new Error(`Invalid SPQR ${name}: ${value} (expected integer)`);
          })();

  if (bigintValue < min || bigintValue > MAX_UINT64) {
    throw new Error(`Invalid SPQR ${name}: ${value} (expected ${min}-${MAX_UINT64})`);
  }

  return bigintValue;
}

function bigintToSafeNumber(name: string, value: bigint): number {
  if (value > MAX_SAFE_INTEGER_BIGINT) {
    throw new Error(
      `Invalid SPQR ${name}: ${value} exceeds JavaScript safe integer range for local state`
    );
  }
  return Number(value);
}

function normalizeDecodedEpoch(value: bigint): SPQRWireEpoch {
  return value <= MAX_SAFE_INTEGER_BIGINT ? Number(value) : value;
}

/**
 * Encode a non-negative integer as an unsigned LEB128 varint.
 *
 * @param value - Value to encode (0 to 2^64-1)
 * @param into - Target buffer
 * @param offset - Write position
 * @returns New offset after the encoded bytes
 */
export function encodeVarintLEB128(value: SPQRWireEpoch, into: Uint8Array, offset: number): number {
  let v = assertUint64('varint', value);
  while (v >= 0x80n) {
    into[offset++] = Number((v & 0x7fn) | 0x80n);
    v >>= 7n;
  }
  into[offset++] = Number(v);
  return offset;
}

/**
 * Decode an unsigned LEB128 varint to bigint.
 *
 * @param from - Source buffer
 * @param cursor - Object with `value` property as read position (mutated)
 * @returns Decoded integer
 */
export function decodeVarintLEB128Bigint(from: Uint8Array, cursor: { value: number }): bigint {
  let result = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (cursor.value < from.length && bytesRead < MAX_VARINT_U64_BYTES) {
    const byte = from[cursor.value++];
    result |= BigInt(byte & 0x7f) << shift;
    bytesRead++;
    if ((byte & 0x80) === 0) {
      if (result > MAX_UINT64) {
        throw new Error('Varint too large (> uint64)');
      }
      return result;
    }
    shift += 7n;
  }

  if (bytesRead >= MAX_VARINT_U64_BYTES) {
    throw new Error('Varint too long (> 10 bytes for uint64)');
  }

  throw new Error('Unexpected end of varint');
}

/**
 * Decode an unsigned LEB128 varint that must fit in uint32.
 */
export function decodeVarintLEB128(from: Uint8Array, cursor: { value: number }): number {
  const value = decodeVarintLEB128Bigint(from, cursor);
  if (value > BigInt(MAX_UINT32)) {
    throw new Error('Varint too large for uint32');
  }
  return Number(value);
}

/**
 * Calculate the number of bytes needed to encode a varint.
 */
function varintSize(value: SPQRWireEpoch): number {
  let v = assertUint64('varint', value);
  let size = 1;
  while (v >= 0x80n) {
    v >>= 7n;
    size++;
  }
  return size;
}

function assertUint32(name: string, value: number, min: number, max = MAX_UINT32): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`Invalid SPQR ${name}: ${value} (expected ${min}-${max})`);
  }
}

function assertBraidMessageType(msgType: number): void {
  if (msgType > MAX_BRAID_MSG_TYPE && msgType !== MODE_NONE) {
    throw new Error(`Invalid braidMsgType: ${msgType} (expected 0-${MAX_BRAID_MSG_TYPE})`);
  }
  assertUint32('braid message type', msgType, 0, MAX_BRAID_MSG_TYPE);
}

function braidMessageTypeRequiresChunk(msgType: number): boolean {
  return msgType !== MODE_NONE && msgType !== BRAID_CT1_ACK_MSG_TYPE;
}

/**
 * Convert an internal SPQR KDF epoch to the reference format's one-based wire epoch.
 */
export function spqrInternalEpochToWireEpoch(epoch: number): number {
  assertUint32('internal epoch', epoch, 0, MAX_UINT32 - 1);
  return epoch + 1;
}

/**
 * Convert the reference format's one-based SPQR wire epoch to the internal KDF epoch.
 *
 * The public wire format accepts u64 epochs per the current SPQR specification
 * reference. This package's direct SPQR state still stores epochs as JS
 * numbers, so direct-mode callers must stay within the safe integer range.
 */
export function spqrWireEpochToInternalEpoch(wireEpoch: SPQRWireEpoch): number {
  const epoch = assertUint64('wire epoch', wireEpoch, 1n);
  return bigintToSafeNumber('internal epoch', epoch - 1n);
}

/**
 * Convert a decoded wire epoch to bigint for braid state-machine calls.
 */
export function spqrWireEpochToBigInt(wireEpoch: SPQRWireEpoch): bigint {
  return assertUint64('wire epoch', wireEpoch, 1n);
}

// ============================================================================
// Encode
// ============================================================================

/**
 * Encode an SPQRWireMessage to compact binary format.
 *
 * For V1 braid: VERSION(1) | VARINT(epoch) | VARINT(chainIndex) | MSG_TYPE(1) | [VARINT(chunkIndex) | CHUNK(32)]
 * For V1 direct: VERSION(1) | VARINT(epoch) | VARINT(chainIndex) | MODE(1) | payload
 * For V1 none: VERSION(1) | VARINT(epoch) | VARINT(chainIndex) | 0x00
 *
 * @param msg - Message to encode
 * @returns Encoded bytes
 */
export function encodeSPQRWire(msg: SPQRWireMessage): Uint8Array {
  if (msg.version !== 1) {
    throw new Error(`Unsupported SPQR wire version for encode: ${msg.version}; v1 is required`);
  }

  if (msg.epoch === undefined) {
    throw new Error('SPQR wire epoch is required');
  }

  const epoch = msg.epoch;
  const chainIndex = msg.chainIndex ?? 0;
  assertUint64('wire epoch', epoch, 1n);
  assertUint32('chain index', chainIndex, 0);

  // Calculate total size
  let size = 1; // version byte
  size += varintSize(epoch);
  size += varintSize(chainIndex);
  size += 1; // mode/type byte

  if (msg.mode === 'braid') {
    const msgType = msg.braidMsgType ?? MODE_NONE;
    assertBraidMessageType(msgType);
    const hasChunk = !!msg.braidChunkData;
    if (braidMessageTypeRequiresChunk(msgType)) {
      if (!hasChunk) {
        throw new Error(`Missing braid chunk for message type: ${msgType}`);
      }
      size += varintSize(msg.braidChunkIndex ?? 0);
      size += BRAID_CHUNK_SIZE;
    } else if (hasChunk) {
      throw new Error(`Unexpected braid chunk for message type: ${msgType}`);
    }
  } else if (msg.mode === 'direct') {
    const hasCiphertext = !!msg.kyberCiphertext;
    const hasPublicKey = !!msg.kyberPublicKey;
    if (hasCiphertext) size += MLKEM768_CIPHERTEXT_SIZE;
    if (hasPublicKey) size += MLKEM768_PUBLIC_KEY_SIZE;
  }

  const buf = new Uint8Array(size);
  let offset = 0;

  // Version byte
  buf[offset++] = VERSION_V1;

  // Epoch (varint)
  offset = encodeVarintLEB128(epoch, buf, offset);

  // Chain index (varint)
  offset = encodeVarintLEB128(chainIndex, buf, offset);

  if (msg.mode === 'braid') {
    // Braid mode: write MSG_TYPE, then the required chunk.
    const msgType = msg.braidMsgType ?? MODE_NONE;
    assertBraidMessageType(msgType);
    buf[offset++] = msgType;

    if (braidMessageTypeRequiresChunk(msgType)) {
      const braidChunkIndex = msg.braidChunkIndex ?? 0;
      assertBraidChunkIndex(braidChunkIndex, 'braid chunk index');
      offset = encodeVarintLEB128(braidChunkIndex, buf, offset);
      buf.set(msg.braidChunkData!, offset);
      offset += BRAID_CHUNK_SIZE;
    }
  } else if (msg.mode === 'direct') {
    // Direct mode: high MSG_TYPE byte + payloads
    const hasCiphertext = !!msg.kyberCiphertext;
    const hasPublicKey = !!msg.kyberPublicKey;

    if (hasCiphertext && hasPublicKey) {
      buf[offset++] = DIRECT_BOTH;
    } else if (hasCiphertext) {
      buf[offset++] = DIRECT_CIPHERTEXT;
    } else if (hasPublicKey) {
      buf[offset++] = DIRECT_PUBLIC_KEY;
    } else {
      buf[offset++] = MODE_NONE;
    }

    if (hasCiphertext) {
      buf.set(msg.kyberCiphertext!, offset);
      offset += MLKEM768_CIPHERTEXT_SIZE;
    }
    if (hasPublicKey) {
      buf.set(msg.kyberPublicKey!, offset);
      offset += MLKEM768_PUBLIC_KEY_SIZE;
    }
  } else {
    // None mode: header-only
    buf[offset++] = MODE_NONE;
  }

  return buf;
}

// ============================================================================
// Decode
// ============================================================================

/**
 * Decode compact binary SPQR wire format to SPQRWireMessage.
 *
 * Empty input is rejected because this package requires SPQR v1.
 *
 * @param bytes - Wire bytes from SignalMessage field 5
 * @returns Decoded message
 */
export function decodeSPQRWire(bytes: Uint8Array): SPQRWireMessage {
  if (!bytes || bytes.length === 0) {
    throw new Error('Missing SPQR wire payload: v1 is required');
  }

  const cursor = { value: 0 };

  // Version byte
  const version = bytes[cursor.value++];
  if (version === 0) {
    throw new Error('Unsupported SPQR wire version: 0; v1 is required');
  }

  if (version !== VERSION_V1) {
    throw new Error(`Unknown SPQR wire version: ${version}`);
  }

  // Epoch (varint)
  const epochBigint = decodeVarintLEB128Bigint(bytes, cursor);
  spqrWireEpochToBigInt(epochBigint);
  const epoch = normalizeDecodedEpoch(epochBigint);

  // Chain index (varint)
  const chainIndex = decodeVarintLEB128(bytes, cursor);
  assertUint32('chain index', chainIndex, 0);

  // Mode/type byte
  if (cursor.value >= bytes.length) {
    throw new Error('Truncated SPQR wire payload: missing mode byte');
  }
  const modeByte = bytes[cursor.value++];

  // Direct mode (0x80, 0x81, 0x82 only)
  // The reference implementation validates this enum strictly — reject unknown values
  if (
    modeByte === DIRECT_CIPHERTEXT ||
    modeByte === DIRECT_PUBLIC_KEY ||
    modeByte === DIRECT_BOTH
  ) {
    const msg: SPQRWireMessage = {
      version,
      epoch,
      chainIndex,
      mode: 'direct',
    };

    if (modeByte === DIRECT_CIPHERTEXT || modeByte === DIRECT_BOTH) {
      if (cursor.value + MLKEM768_CIPHERTEXT_SIZE > bytes.length) {
        throw new Error(
          `Truncated kyberCiphertext: need ${MLKEM768_CIPHERTEXT_SIZE} bytes at offset ${cursor.value}, have ${bytes.length - cursor.value}`
        );
      }
      msg.kyberCiphertext = bytes.slice(cursor.value, cursor.value + MLKEM768_CIPHERTEXT_SIZE);
      cursor.value += MLKEM768_CIPHERTEXT_SIZE;
    }
    if (modeByte === DIRECT_PUBLIC_KEY || modeByte === DIRECT_BOTH) {
      if (cursor.value + MLKEM768_PUBLIC_KEY_SIZE > bytes.length) {
        throw new Error(
          `Truncated kyberPublicKey: need ${MLKEM768_PUBLIC_KEY_SIZE} bytes at offset ${cursor.value}, have ${bytes.length - cursor.value}`
        );
      }
      msg.kyberPublicKey = bytes.slice(cursor.value, cursor.value + MLKEM768_PUBLIC_KEY_SIZE);
      cursor.value += MLKEM768_PUBLIC_KEY_SIZE;
    }

    return msg;
  }

  // None mode (0x00)
  if (modeByte === MODE_NONE) {
    return { version, epoch, chainIndex, mode: 'none' };
  }

  // Braid mode (0x01-0x06, matching the profile MessageType enum)
  if (modeByte > MAX_BRAID_MSG_TYPE) {
    throw new Error(`Unknown SPQR mode byte: 0x${modeByte.toString(16).padStart(2, '0')}`);
  }

  const msg: SPQRWireMessage = {
    version,
    epoch,
    chainIndex,
    mode: 'braid',
    braidMsgType: modeByte,
  };

  // The reference Ct1Ack payload is a bare acknowledgement. It intentionally has no
  // chunk; trailing bytes are allowed for future protocol upgrades.
  if (!braidMessageTypeRequiresChunk(modeByte)) {
    return msg;
  }

  if (cursor.value >= bytes.length) {
    throw new Error(`Missing braid chunk for message type: ${modeByte}`);
  }

  const braidChunkIndex = decodeVarintLEB128(bytes, cursor);
  assertBraidChunkIndex(braidChunkIndex, 'braid chunk index');
  msg.braidChunkIndex = braidChunkIndex;
  if (cursor.value + BRAID_CHUNK_SIZE > bytes.length) {
    throw new Error(
      `Truncated braid chunk: need ${BRAID_CHUNK_SIZE} bytes at offset ${cursor.value}, have ${bytes.length - cursor.value}`
    );
  }
  msg.braidChunkData = bytes.slice(cursor.value, cursor.value + BRAID_CHUNK_SIZE);
  cursor.value += BRAID_CHUNK_SIZE;

  return msg;
}
