/**
 * Shared Protobuf Encoding Primitives
 *
 * Low-level protobuf wire format encoding/decoding. Two kinds of caller use it:
 * binary formats that aren't full protobuf messages (MAC headers, safety number
 * fingerprints, sealed sender envelope framing), and the hand-written static
 * codecs for the message schemas in this package.
 *
 * Implements a subset of the Protocol Buffers encoding spec:
 * - Varint encoding (wire type 0), 32-bit and 64-bit
 * - Fixed 64-bit fields (wire type 1)
 * - Length-delimited fields (wire type 2): bytes, strings, embedded messages
 * - Field tags (field_number << 3 | wire_type)
 * - Unknown field skipping
 *
 * The subset is chosen by what the schemas here actually use. Deliberately
 * absent: groups (wire types 3 and 4, deprecated and used by nothing here),
 * packed repeated scalars (no schema here repeats a scalar), sint/zigzag, and
 * negative enum values — each of which would need sign-extended 10-byte
 * varints. `ProtoReader` rejects rather than misreads what it does not cover.
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

/** Protobuf wire type 1: fixed 64-bit, little-endian (fixed64, sfixed64, double) */
export const WIRE_TYPE_FIXED64 = 1;

/** Protobuf wire type 2: length-delimited (bytes, strings, embedded messages) */
export const WIRE_TYPE_LENGTH_DELIMITED = 2;

/** Protobuf wire type 5: fixed 32-bit, little-endian (fixed32, sfixed32, float) */
export const WIRE_TYPE_FIXED32 = 5;

// ============================================================================
// Varint Encoding/Decoding
// ============================================================================

/** Largest value a protobuf uint32 field can carry. */
export const UINT32_MAX = 0xffffffff;

/**
 * Encode an unsigned integer as a varint.
 *
 * Each byte uses 7 bits for data and 1 bit (MSB) as continuation flag.
 * Supports values 0 to 2^32-1 (uint32 range).
 *
 * Anything outside that range is rejected rather than coerced into it. The
 * shift this loop uses is a 32-bit operation, so a larger value used to be
 * truncated to its low 32 bits and emitted as a non-canonical encoding —
 * 2^32 came out as `80 00`, which `decodeVarint64` then refuses, leaving the
 * package writing bytes it cannot read back. A non-integer was worse still:
 * `NaN` encoded as 0 and `1.5` as 1, silently. protobufjs coerced all of
 * these with `>>> 0` and said nothing; nothing in this package has ever had a
 * reason to hand any of them over, so the coercion only ever hid a defect at
 * the call site. Values above uint32 belong in `encodeVarint64`.
 *
 * @param value - Integer in the uint32 range
 * @returns Varint-encoded bytes
 */
export function encodeVarint(value: number): Uint8Array {
  if (value < 0) {
    throw new Error('Varint value must be non-negative');
  }
  if (value > UINT32_MAX) {
    throw new Error('Varint value exceeds uint32 range');
  }
  if (!Number.isInteger(value)) {
    throw new Error('Varint value must be an integer');
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
// 64-bit Varint Encoding/Decoding
// ============================================================================

/** Largest value a protobuf uint64 field can carry. */
export const UINT64_MAX = (1n << 64n) - 1n;

/** A uint64 varint never needs more than ceil(64 / 7) = 10 bytes. */
export const MAX_VARINT64_BYTES = 10;

/**
 * Encode an unsigned 64-bit integer as a varint.
 *
 * Byte-compatible with `encodeVarint` over the uint32 range: both emit the
 * minimal base-128 little-endian form, so a value below 2^32 encodes
 * identically either way. Use this one wherever the schema says uint64 — the
 * SPQR epoch is the case in this package.
 *
 * @param value - Non-negative integer, at most 2^64-1
 * @returns Varint-encoded bytes (1 to 10)
 */
export function encodeVarint64(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error('Varint value must be non-negative');
  }
  if (value > UINT64_MAX) {
    throw new Error('Varint value exceeds uint64 range');
  }

  const bytes: number[] = [];

  // Encode 7 bits at a time, setting high bit if more bytes follow
  while (value > 0x7fn) {
    bytes.push(Number(value & 0x7fn) | 0x80); // 7 bits + continuation bit
    value >>= 7n;
  }
  bytes.push(Number(value)); // Final byte (no continuation)

  return new Uint8Array(bytes);
}

/**
 * Decode a 64-bit varint from bytes at the given offset.
 *
 * Canonical encoding is required: a varint longer than one byte whose last
 * byte is 0x00 encodes a value that fits in fewer bytes, and is rejected. The
 * contract is stricter than protobufjs, which accepts the redundant forms and
 * silently truncates a uint32 field to 32 bits. Two reasons to be strict here:
 * these bytes are signed and MAC'd (SenderKeyMessage signing, sealed sender
 * certificates), and accepting several encodings of one value makes the
 * signed byte string malleable; and byte identity is only checkable when
 * decode-then-encode is the identity function. Every encoder — protobufjs
 * included — emits the canonical form, so nothing this package has ever
 * written is rejected by it.
 *
 * @param bytes - Buffer containing varint
 * @param offset - Starting offset in buffer
 * @returns Decoded value and number of bytes consumed
 */
export function decodeVarint64(
  bytes: Uint8Array,
  offset: number
): { value: bigint; bytesRead: number } {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  for (;;) {
    if (offset + bytesRead >= bytes.length) {
      throw new Error('Varint truncated');
    }

    const byte = bytes[offset + bytesRead]!;
    bytesRead++;

    // Nine bytes carry bits 0..62, so the tenth contributes bit 63 and no
    // more: a payload above 0x01 would carry the value past 2^64-1. The
    // continuation bit is not part of that judgement — a tenth byte that asks
    // for an eleventh is too long, which the check at the foot of the loop
    // reports instead.
    if (bytesRead === MAX_VARINT64_BYTES && (byte & 0x7f) > 0x01) {
      throw new Error('Varint value exceeds uint64 range');
    }

    value |= BigInt(byte & 0x7f) << shift;
    shift += 7n;

    // High bit clear means last byte
    if ((byte & 0x80) === 0) {
      if (bytesRead > 1 && byte === 0x00) {
        throw new Error('Varint is not canonically encoded');
      }
      break;
    }

    if (bytesRead >= MAX_VARINT64_BYTES) {
      throw new Error('Varint too long');
    }
  }

  return { value, bytesRead };
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
 * Encode a uint64 protobuf field (tag + varint value).
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - Uint64 value
 * @returns Encoded field bytes
 */
export function encodeUint64Field(fieldNumber: number, value: bigint): Uint8Array {
  return concatFields(encodeTag(fieldNumber, WIRE_TYPE_VARINT), encodeVarint64(value));
}

/**
 * Encode a bool protobuf field (tag + varint 1 or 0).
 *
 * `false` is encoded, not omitted. Presence is the caller's decision — a
 * schema with proto2 optional semantics distinguishes a set `false` from an
 * absent field, so this helper never drops a value it was handed.
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - Bool value
 * @returns Encoded field bytes
 */
export function encodeBoolField(fieldNumber: number, value: boolean): Uint8Array {
  return concatFields(encodeTag(fieldNumber, WIRE_TYPE_VARINT), encodeVarint(value ? 1 : 0));
}

/**
 * Encode an enum protobuf field (tag + varint value).
 *
 * Enums are varints on the wire, so this is `encodeUint32Field` under a name
 * that says what the schema means. Negative enum values are rejected: the
 * wire form sign-extends them to 10 bytes, and no schema in this package
 * declares one.
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - Enum value (non-negative)
 * @returns Encoded field bytes
 */
export function encodeEnumField(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error('Enum value must be a non-negative integer');
  }
  return encodeUint32Field(fieldNumber, value);
}

/**
 * Encode a fixed64 protobuf field (tag + 8 little-endian bytes).
 *
 * Unlike uint64 this is not a varint: fixed64 always occupies 8 bytes,
 * least-significant byte first. The sealed sender certificate expiry uses it.
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - Uint64 value
 * @returns Encoded field bytes
 */
export function encodeFixed64Field(fieldNumber: number, value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error('Fixed64 value must be non-negative');
  }
  if (value > UINT64_MAX) {
    throw new Error('Fixed64 value exceeds uint64 range');
  }

  const data = new Uint8Array(8);
  let remaining = value;
  for (let i = 0; i < 8; i++) {
    data[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  return concatFields(encodeTag(fieldNumber, WIRE_TYPE_FIXED64), data);
}

/**
 * Encode a string protobuf field (tag + length + UTF-8 bytes).
 *
 * @param fieldNumber - Field number (1-based)
 * @param value - String value
 * @returns Encoded field bytes
 */
export function encodeStringField(fieldNumber: number, value: string): Uint8Array {
  return encodeBytesField(fieldNumber, new TextEncoder().encode(value));
}

/**
 * Encode an embedded-message protobuf field (tag + length + message bytes).
 *
 * A nested message is a length-delimited field whose payload is the encoded
 * submessage, so this is `encodeBytesField` under a name that says so. Encode
 * the child first, then hand its bytes here.
 *
 * @param fieldNumber - Field number (1-based)
 * @param encodedMessage - Already-encoded submessage bytes
 * @returns Encoded field bytes
 */
export function encodeMessageField(fieldNumber: number, encodedMessage: Uint8Array): Uint8Array {
  return encodeBytesField(fieldNumber, encodedMessage);
}

/**
 * Encode a repeated bytes field: one tag-length-value run per element.
 *
 * Length-delimited fields are never packed, so this is exactly what a
 * protobuf encoder emits for `repeated bytes`. An empty list encodes to
 * nothing, which is how an absent repeated field looks on the wire.
 *
 * @param fieldNumber - Field number (1-based)
 * @param values - Elements in order
 * @returns Encoded field bytes
 */
export function encodeRepeatedBytesField(fieldNumber: number, values: Uint8Array[]): Uint8Array {
  // Concatenated from a list rather than by spreading it into `concatFields`:
  // a repeated field's element count is bounded by the message, not by us,
  // and a long list would spread into more arguments than a call accepts.
  return concatAll(values.map((value) => encodeBytesField(fieldNumber, value)));
}

/**
 * Encode a repeated embedded-message field: one tag-length-value run per
 * element, each payload an already-encoded submessage.
 *
 * @param fieldNumber - Field number (1-based)
 * @param encodedMessages - Already-encoded submessages in order
 * @returns Encoded field bytes
 */
export function encodeRepeatedMessageField(
  fieldNumber: number,
  encodedMessages: Uint8Array[]
): Uint8Array {
  return encodeRepeatedBytesField(fieldNumber, encodedMessages);
}

/**
 * Skip an unknown field in a protobuf message.
 *
 * Used during decoding to skip fields we don't recognize, enabling
 * forward compatibility with newer message versions.
 *
 * Handles the two wire types the non-message binary formats use. The static
 * message codecs skip through `ProtoReader.skipField`, which also covers the
 * fixed-width wire types and bounds-checks against the buffer end.
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
  return concatAll(arrays);
}

/**
 * Concatenate a list of Uint8Arrays into one.
 *
 * The same work as `concatFields` without spreading the list into arguments,
 * for callers whose element count the message decides.
 */
function concatAll(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// ============================================================================
// Message Reader
// ============================================================================

/** `UINT32_MAX` in the width the reader decodes varints to. */
const UINT32_MAX_BIGINT = BigInt(UINT32_MAX);

/** Largest assignable protobuf field number (2^29-1). */
const MAX_FIELD_NUMBER = 536870911n;

/**
 * Cursor over one encoded protobuf message.
 *
 * Every message decoder is the same loop — read a tag, dispatch on the field
 * number, skip what it does not know — and this owns that loop's bookkeeping
 * so seventeen hand-written codecs do not each repeat it:
 *
 * ```ts
 * const reader = new ProtoReader(bytes);
 * while (reader.hasMore()) {
 *   const { fieldNumber } = reader.readTag();
 *   switch (fieldNumber) {
 *     case 1: ratchetKey = reader.readBytes(); break;
 *     case 2: counter = reader.readUint32(); break;
 *     default: reader.skipField();
 *   }
 * }
 * ```
 *
 * The read methods check the tag's wire type against the type they are being
 * asked to read and throw on a mismatch, so a field that arrives with the
 * wrong wire type is rejected instead of misparsed. (protobufjs reads the
 * declared type regardless and can silently produce nonsense.) That is why
 * `readTag` must precede every read: the wire type it recorded is what the
 * next read validates against.
 *
 * Every read is bounded by the buffer, so a length prefix that points past
 * the end throws rather than allocating. Callers still apply their own
 * message-size ceiling before constructing a reader.
 */
export class ProtoReader {
  private readonly bytes: Uint8Array;
  private cursor: number;
  private wireType: number | null = null;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.cursor = 0;
  }

  /** Offset of the next unread byte. */
  get offset(): number {
    return this.cursor;
  }

  /** True while unread bytes remain. */
  hasMore(): boolean {
    return this.cursor < this.bytes.length;
  }

  /**
   * Read the next field tag and remember its wire type for the read that
   * follows.
   *
   * @returns Field number and wire type
   */
  readTag(): { fieldNumber: number; wireType: number } {
    const { value: tag, bytesRead } = decodeVarint64(this.bytes, this.cursor);
    this.cursor += bytesRead;

    const number = tag >> 3n;
    const wireType = Number(tag & 0x07n);

    // Neither 0 nor anything above 2^29-1 is an assignable field number, so a
    // tag carrying one is a corrupt stream rather than an unknown field to be
    // skipped. Checking the bound also keeps the conversion below exact.
    if (number === 0n || number > MAX_FIELD_NUMBER) {
      throw new Error(`Invalid protobuf field number: ${number}`);
    }
    const fieldNumber = Number(number);

    this.wireType = wireType;
    return { fieldNumber, wireType };
  }

  /** Read a uint32 field value. */
  readUint32(): number {
    const value = this.readVarintValue();
    if (value > UINT32_MAX_BIGINT) {
      throw new Error('Varint value exceeds uint32 range');
    }
    return Number(value);
  }

  /** Read a uint64 field value. */
  readUint64(): bigint {
    return this.readVarintValue();
  }

  /** Read a bool field value. Any non-zero varint is `true`, per the spec. */
  readBool(): boolean {
    return this.readVarintValue() !== 0n;
  }

  /**
   * Read an enum field value.
   *
   * Enums are varints. Values outside the uint32 range are rejected — they can
   * only be the sign-extended negatives this package's schemas never declare.
   */
  readEnum(): number {
    return this.readUint32();
  }

  /** Read a fixed64 field value (8 little-endian bytes). */
  readFixed64(): bigint {
    this.expectWireType(WIRE_TYPE_FIXED64);
    const end = this.cursor + 8;
    if (end > this.bytes.length) {
      throw new Error('Fixed64 field truncated');
    }

    let value = 0n;
    for (let i = 7; i >= 0; i--) {
      value = (value << 8n) | BigInt(this.bytes[this.cursor + i]!);
    }
    this.cursor = end;
    return value;
  }

  /**
   * Read a bytes field value.
   *
   * The result is a copy, so the decoded message does not alias — and cannot
   * be mutated through — the input buffer.
   */
  readBytes(): Uint8Array {
    this.expectWireType(WIRE_TYPE_LENGTH_DELIMITED);
    const end = this.readLengthPrefix();
    const data = this.bytes.slice(this.cursor, end);
    this.cursor = end;
    return data;
  }

  /** Read a string field value, decoded from UTF-8. */
  readString(): string {
    return new TextDecoder().decode(this.readBytes());
  }

  /**
   * Read an embedded-message field value as its encoded bytes.
   *
   * Hand the result to the child message's decoder. Identical on the wire to
   * `readBytes`; the name says which the schema meant.
   */
  readMessage(): Uint8Array {
    return this.readBytes();
  }

  /**
   * Skip the field whose tag was just read.
   *
   * Groups (wire types 3 and 4) are rejected rather than skipped: they are
   * deprecated, no schema here uses them, and skipping them correctly means
   * matching nested end-group tags, which is machinery with no caller.
   */
  skipField(): void {
    const wireType = this.takeWireType();

    switch (wireType) {
      case WIRE_TYPE_VARINT: {
        const { bytesRead } = decodeVarint64(this.bytes, this.cursor);
        this.cursor += bytesRead;
        return;
      }
      case WIRE_TYPE_FIXED64:
        this.advance(8, 'Fixed64 field truncated');
        return;
      case WIRE_TYPE_LENGTH_DELIMITED:
        this.cursor = this.readLengthPrefix();
        return;
      case WIRE_TYPE_FIXED32:
        this.advance(4, 'Fixed32 field truncated');
        return;
      default:
        throw new Error(`Unsupported wire type: ${wireType}`);
    }
  }

  /** Read a varint value after checking the tag said wire type 0. */
  private readVarintValue(): bigint {
    this.expectWireType(WIRE_TYPE_VARINT);
    const { value, bytesRead } = decodeVarint64(this.bytes, this.cursor);
    this.cursor += bytesRead;
    return value;
  }

  /**
   * Consume the length prefix of a length-delimited field.
   *
   * @returns Offset one past the field's payload
   */
  private readLengthPrefix(): number {
    const { value: length, bytesRead } = decodeVarint64(this.bytes, this.cursor);
    this.cursor += bytesRead;

    // Compare in bigint: a length near 2^64 would lose precision as a Number
    // and could compare as in-bounds.
    const end = BigInt(this.cursor) + length;
    if (end > BigInt(this.bytes.length)) {
      throw new Error('Length-delimited field extends past the end of the message');
    }
    return Number(end);
  }

  private advance(count: number, message: string): void {
    if (this.cursor + count > this.bytes.length) {
      throw new Error(message);
    }
    this.cursor += count;
  }

  private expectWireType(expected: number): void {
    const wireType = this.takeWireType();
    if (wireType !== expected) {
      throw new Error(`Expected wire type ${expected}, got ${wireType}`);
    }
  }

  /**
   * Take the wire type recorded by `readTag`, clearing it so a second read
   * without an intervening tag fails loudly instead of reusing it.
   */
  private takeWireType(): number {
    if (this.wireType === null) {
      throw new Error('No field tag has been read');
    }
    const wireType = this.wireType;
    this.wireType = null;
    return wireType;
  }
}
