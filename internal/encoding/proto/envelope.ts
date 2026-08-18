/**
 * Signal Protocol Envelope Framing
 *
 * Implements version-byte framing and MAC extraction for SignalProtocolMessage and
 * PreKeySignalProtocolMessage.
 *
 * ## Wire Formats
 *
 * **SignalProtocolMessage** (Double Ratchet message):
 * ```
 * [version_byte(1)] [protobuf_bytes(N)] [MAC(8)]
 * ```
 * - version_byte: `(message_version << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION`
 * - MAC: trailing 8-byte HMAC-SHA256 truncated tag
 *
 * **PreKeySignalProtocolMessage** (initial key exchange + first message):
 * ```
 * [version_byte(1)] [protobuf_bytes(N)]
 * ```
 * - No trailing MAC (the inner SignalProtocolMessage carries its own MAC)
 *
 * ## Version Byte Layout
 *
 * The version byte packs two 4-bit values:
 * - High nibble: message version (currently 4)
 * - Low nibble: CIPHERTEXT_MESSAGE_CURRENT_VERSION (always 4)
 *
 * For current protocol version 4: `(4 << 4) | 4 = 0x44`
 *
 * @internal
 */

// ============================================================================
// Constants
// ============================================================================

/**
 * Current Signal Protocol ciphertext message version.
 *
 * Version 4 enables PQXDH and KEM prekey fields.
 */
export {};
export const CIPHERTEXT_MESSAGE_CURRENT_VERSION = 4;

/**
 * Length of the MAC appended to framed SignalProtocolMessages.
 *
 * HMAC-SHA256 output truncated to 8 bytes.
 */
export const MAC_LENGTH = 8;

// ============================================================================
// Version Byte
// ============================================================================

/**
 * Construct the version byte for a Signal Protocol message.
 *
 * The version byte layout is: `(message_version << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION`
 *
 * For the current protocol version 4 this produces `0x44`.
 *
 * @param version - Message version (defaults to CIPHERTEXT_MESSAGE_CURRENT_VERSION)
 * @returns The version byte value (0x00-0xFF)
 *
 */
export function makeVersionByte(version: number = CIPHERTEXT_MESSAGE_CURRENT_VERSION): number {
  return ((version << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION) & 0xff;
}

/**
 * Extract the message version from the first byte of a framed message.
 *
 * Reads the high nibble of the version byte: `bytes[0] >> 4`
 *
 * @param bytes - Framed message bytes (at least 1 byte)
 * @returns The message version number
 * @throws Error if the input is empty
 */
export function getMessageVersion(bytes: Uint8Array): number {
  if (bytes.length === 0) {
    throw new Error('Cannot read version from empty message');
  }
  return bytes[0]! >> 4;
}

// ============================================================================
// SignalProtocolMessage Framing
// ============================================================================

/**
 * Frame a SignalProtocolMessage for wire transport.
 *
 * Concatenates: `[version_byte] [protobuf_bytes] [mac]`
 *
 * The version byte defaults to the current protocol version (0x44).
 * The MAC must be exactly `MAC_LENGTH` (8) bytes.
 *
 * @param protobufBytes - Protobuf-encoded SignalProtocolMessage (from `encodeSignalProtocolMessage()`)
 * @param macBytes - 8-byte HMAC-SHA256 truncated tag
 * @returns Framed message bytes ready for transport
 * @throws Error if macBytes is not exactly MAC_LENGTH bytes
 */
export function frameSignalProtocolMessage(protobufBytes: Uint8Array, macBytes: Uint8Array): Uint8Array {
  if (macBytes.length !== MAC_LENGTH) {
    throw new Error(`MAC must be exactly ${MAC_LENGTH} bytes, got ${macBytes.length}`);
  }

  const result = new Uint8Array(1 + protobufBytes.length + MAC_LENGTH);
  result[0] = makeVersionByte();
  result.set(protobufBytes, 1);
  result.set(macBytes, 1 + protobufBytes.length);
  return result;
}

/**
 * Parse a framed SignalProtocolMessage envelope into its components.
 *
 * Splits: `[version_byte(1)] [protobuf_bytes(N)] [MAC(8)]`
 *
 * The caller should validate the MAC and decode the protobuf bytes
 * separately using `decodeSignalProtocolMessage()`.
 *
 * @param bytes - Framed SignalProtocolMessage bytes
 * @returns Parsed envelope with version, protobuf bytes, and MAC
 * @throws Error if the message is too short to contain version + MAC
 */
export function parseSignalProtocolMessageEnvelope(bytes: Uint8Array): {
  version: number;
  protobufBytes: Uint8Array;
  mac: Uint8Array;
} {
  // Minimum: 1 (version) + 0 (protobuf) + 8 (MAC) = 9 bytes
  const minLength = 1 + MAC_LENGTH;
  if (bytes.length < minLength) {
    throw new Error(
      `SignalProtocolMessage too short: expected at least ${minLength} bytes, got ${bytes.length}`
    );
  }

  const version = bytes[0]! >> 4;
  const protobufBytes = bytes.slice(1, bytes.length - MAC_LENGTH);
  const mac = bytes.slice(bytes.length - MAC_LENGTH);

  return { version, protobufBytes, mac };
}

// ============================================================================
// PreKeySignalProtocolMessage Framing
// ============================================================================

/**
 * Frame a PreKeySignalProtocolMessage for wire transport.
 *
 * Concatenates: `[version_byte] [protobuf_bytes]`
 *
 * No trailing MAC. The inner SignalProtocolMessage (in the `message` field)
 * carries its own MAC.
 *
 * @param protobufBytes - Protobuf-encoded PreKeySignalProtocolMessage (from `encodePreKeySignalProtocolMessage()`)
 * @returns Framed message bytes ready for transport
 */
export function framePreKeySignalProtocolMessage(protobufBytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(1 + protobufBytes.length);
  result[0] = makeVersionByte();
  result.set(protobufBytes, 1);
  return result;
}

/**
 * Parse a framed PreKeySignalProtocolMessage envelope into its components.
 *
 * Splits: `[version_byte(1)] [protobuf_bytes(N)]`
 *
 * The caller should decode the protobuf bytes separately using
 * `decodePreKeySignalProtocolMessage()`.
 *
 * @param bytes - Framed PreKeySignalProtocolMessage bytes
 * @returns Parsed envelope with version and protobuf bytes
 * @throws Error if the message is too short to contain a version byte
 */
export function parsePreKeySignalProtocolMessageEnvelope(bytes: Uint8Array): {
  version: number;
  protobufBytes: Uint8Array;
} {
  if (bytes.length < 1) {
    throw new Error(`PreKeySignalProtocolMessage too short: expected at least 1 byte, got ${bytes.length}`);
  }

  const version = bytes[0]! >> 4;
  const protobufBytes = bytes.slice(1);

  return { version, protobufBytes };
}
