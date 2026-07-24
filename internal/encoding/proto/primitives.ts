/**
 * Shared Protobuf Encoding Primitives
 *
 * Low-level protobuf wire format encoding/decoding used for binary formats
 * that aren't full protobuf messages (MAC headers, safety number fingerprints,
 * sealed sender envelope framing).
 *
 * Implements a subset of the Protocol Buffers encoding spec:
 * - Varint encoding (wire type 0)
 * - Length-delimited fields (wire type 2)
 * - Field tags (field_number << 3 | wire_type)
 * - Unknown field skipping
 *
 * @see https://protobuf.dev/programming-guides/encoding/
 * @internal
 */

// ============================================================================
// Wire Type Constants
// ============================================================================

/** Protobuf wire type 0: variable-length integer */
export {};
export const WIRE_TYPE_VARINT = 0;

/** Protobuf wire type 2: length-delimited (bytes, strings, embedded messages) */
export const WIRE_TYPE_LENGTH_DELIMITED = 2;

// ============================================================================
// Varint Encoding/Decoding
// ============================================================================

/**
 * Encode an unsigned integer as a varint.
 *
 * Each byte uses 7 bits for data and 1 bit (MSB) as continuation flag.
 * Supports values 0 to 2^32-1 (uint32 range).
 *
 * @param value - Non-negative integer to encode
 * @returns Varint-encoded bytes
 */
export function encodeVarint(value: number): Uint8Array {
  if (value < 0) {
    throw new Error('Varint value must be non-negative');
  }

  const bytes: number[] = [];

  // Encode 7 bits at a time, setting high bit if more bytes follow
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80); // 7 bits + continuation bit
    value >>>= 7;
  }
  bytes.push(value & 0x7f); // Final byte (no continuation)

  return new Uint8Array(bytes.length > 0 ? bytes : [0]);
}

/**
 * Decode a varint from bytes at the given offset.
 *
 * @param bytes - Buffer containing varint
 * @param offset - Starting offset in buffer
 * @returns Decoded value and number of bytes consumed
 */
export function decodeVarint(
  bytes: Uint8Array,
  offset: number
): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead]!;
    bytesRead++;

    value |= (byte & 0x7f) << shift;
    shift += 7;

    // High bit clear means last byte
    if ((byte & 0x80) === 0) {
      break;
    }

    // Prevent overflow (max 5 bytes for 32-bit)
    if (bytesRead >= 5) {
      throw new Error('Varint too long');
    }
  }

  return { value: value >>> 0, bytesRead };
}

// ============================================================================
// Field Tag Encoding/Decoding
// ============================================================================

/**
 * Encode a protobuf field tag.
 *
 * Tag = (field_number << 3) | wire_type
 *
 * @param fieldNumber - Field number (1-based)
 * @param wireType - Wire type (0=varint, 2=length-delimited)
 * @returns Encoded tag as varint
 */
export function encodeTag(fieldNumber: number, wireType: number): Uint8Array {
  return encodeVarint((fieldNumber << 3) | wireType);
}

/**
 * Decode a protobuf field tag from bytes.
 *
 * @param bytes - Buffer containing the tag
 * @param offset - Starting offset in buffer
 * @returns Decoded field number, wire type, and bytes consumed
 */
export function decodeTag(
  bytes: Uint8Array,
  offset: number
): {
  fieldNumber: number;
  wireType: number;
  bytesRead: number;
} {
  const { value: tag, bytesRead } = decodeVarint(bytes, offset);
  return {
    fieldNumber: tag >>> 3,
    wireType: tag & 0x07,
    bytesRead,
  };
}

// ============================================================================
// Field-Level Helpers
// ============================================================================

/**
 * Encode a uint32 protobuf field (tag + varint value).
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - Uint32 value
 * @returns Encoded field bytes
 */
export function encodeUint32Field(fieldNumber: number, value: number): Uint8Array {
  const tag = encodeTag(fieldNumber, WIRE_TYPE_VARINT);
  const val = encodeVarint(value);
  const result = new Uint8Array(tag.length + val.length);
  result.set(tag, 0);
  result.set(val, tag.length);
  return result;
}

/**
 * Encode a bytes/string protobuf field (tag + length + data).
 *
 * @param fieldNumber - Field number (1-based)
 * @param data - Raw bytes to encode
 * @returns Encoded field bytes
 */
export function encodeBytesField(fieldNumber: number, data: Uint8Array): Uint8Array {
  const tag = encodeTag(fieldNumber, WIRE_TYPE_LENGTH_DELIMITED);
  const len = encodeVarint(data.length);
  const result = new Uint8Array(tag.length + len.length + data.length);
  result.set(tag, 0);
  result.set(len, tag.length);
  result.set(data, tag.length + len.length);
  return result;
}

/**
 * Skip an unknown field in a protobuf message.
 *
 * Used during decoding to skip fields we don't recognize, enabling
 * forward compatibility with newer message versions.
 *
 * @param wireType - Wire type of the field to skip
 * @param bytes - Buffer containing the field data
 * @param offset - Current offset (after the tag)
 * @returns New offset after skipping the field
 */
export function skipUnknownField(wireType: number, bytes: Uint8Array, offset: number): number {
  if (wireType === WIRE_TYPE_VARINT) {
    const { bytesRead } = decodeVarint(bytes, offset);
    return offset + bytesRead;
  } else if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
    const { value: length, bytesRead: lengthBytes } = decodeVarint(bytes, offset);
    return offset + lengthBytes + length;
  } else {
    throw new Error(`Unsupported wire type: ${wireType}`);
  }
}

// ============================================================================
// Utility: Concatenate byte arrays
// ============================================================================

/**
 * Concatenate multiple Uint8Arrays into one.
 *
 * @param arrays - Arrays to concatenate
 * @returns Single concatenated array
 */
export function concatFields(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
