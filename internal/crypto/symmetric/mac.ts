/**
 * Message MAC Computation and Header Serialization
 *
 * Implements identity-bound MAC computation for Signal Protocol Section 3
 * (plaintext headers with MAC authentication).
 *
 * This replaces header encryption (Section 4) with:
 * - Plaintext headers containing DH public key, message number, and previous chain length
 * - HMAC-SHA256 truncated to 8 bytes
 * - Identity key binding in MAC computation (prevents cross-session replay)
 *
 * Header Serialization:
 * Uses the SignalMessage protobuf field encoding.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/ (Section 3)
 */

import { hmac } from './hmac';
import { concatBytes, base64ToBytes, bytesToBase64, constantTimeEqual } from '../utils';
import type { Base64 } from '../../../types/utils';
import { DJB_KEY_TYPE } from '../key-prefix';
import {
  encodeVarint,
  decodeVarint,
  encodeTag,
  skipUnknownField,
  WIRE_TYPE_VARINT,
  WIRE_TYPE_LENGTH_DELIMITED,
} from '../../encoding/proto/primitives';

// ============================================================================
// Constants
// ============================================================================

/**
 * Signal Protocol message version byte.
 *
 * The value 0x33 encodes:
 * - High nibble (3): Current message version
 * - Low nibble (3): Supported message version
 *
 * Included in MAC computation for protocol versioning.
 */
export {};
export const MESSAGE_VERSION_BYTE = 0x33;

/**
 * Truncated MAC length in bytes.
 *
 * Signal Protocol uses HMAC-SHA256 truncated to 8 bytes (64 bits).
 * Per spec Section 7.2 - "truncating to 128 bits is acceptable...
 * in no case less than 64 bits."
 *
 * This SDK uses an 8-byte tag for this wire format.
 */
export const MAC_LENGTH_BYTES = 8;

// Re-export DJB_KEY_TYPE for backwards compatibility
// (imported from key-prefix.ts above)
export { DJB_KEY_TYPE };

// ============================================================================
// Header Serialization (Protobuf-Compatible)
// ============================================================================

/**
 * Serialize a message header using protobuf encoding.
 *
 * SignalMessage header fields:
 * - Field 1 (bytes): ratchet_key (33 bytes: 0x05 prefix + 32-byte X25519 key)
 * - Field 2 (uint32): counter (message number N)
 * - Field 3 (uint32): previous_counter (previous chain length PN)
 *
 * The serialized bytes are included in MAC computation and can optionally
 * be embedded in the message for full protobuf wire format compatibility.
 *
 * @param ratchetKey - Sender's current ratchet public key (Base64)
 * @param previousCounter - Number of messages in previous sending chain (PN)
 * @param counter - Current message counter in sending chain (N)
 * @returns Protobuf-encoded header bytes
 *
 * @example
 * ```typescript
 * const headerBytes = serializeHeader(
 *   "base64EncodedPublicKey...",
 *   5,   // previous_counter: previous chain had 5 messages
 *   12   // counter: this is message 12 in current chain
 * );
 * ```
 */
export function serializeHeader(
  ratchetKey: Base64 | string,
  previousCounter: number,
  counter: number
): Uint8Array {
  // Validate inputs
  if (previousCounter < 0 || previousCounter > 0xffffffff) {
    throw new Error('previousCounter must be 0 to 2^32-1');
  }
  if (counter < 0 || counter > 0xffffffff) {
    throw new Error('counter must be 0 to 2^32-1');
  }

  // Decode ratchet public key
  const ratchetKeyBytes = base64ToBytes(ratchetKey as Base64);
  if (ratchetKeyBytes.length !== 32) {
    throw new Error(`Ratchet key must be 32 bytes, got ${ratchetKeyBytes.length}`);
  }

  // Build protobuf fields

  // Field 1: ratchet_key (bytes) - 33 bytes with DJB prefix
  const keyWithPrefix = new Uint8Array(33);
  keyWithPrefix[0] = DJB_KEY_TYPE;
  keyWithPrefix.set(ratchetKeyBytes, 1);

  const field1Tag = encodeTag(1, WIRE_TYPE_LENGTH_DELIMITED);
  const field1Length = encodeVarint(keyWithPrefix.length);
  const field1 = concatBytes(field1Tag, field1Length, keyWithPrefix);

  // Field 2: counter (uint32) - message counter
  const field2Tag = encodeTag(2, WIRE_TYPE_VARINT);
  const field2Value = encodeVarint(counter);
  const field2 = concatBytes(field2Tag, field2Value);

  // Field 3: previous_counter (uint32) - previous chain length
  const field3Tag = encodeTag(3, WIRE_TYPE_VARINT);
  const field3Value = encodeVarint(previousCounter);
  const field3 = concatBytes(field3Tag, field3Value);

  // Concatenate all fields
  return concatBytes(field1, field2, field3);
}

/**
 * Deserialize a protobuf-encoded message header.
 *
 * @param bytes - Protobuf-encoded header bytes
 * @returns Parsed SignalMessage header fields
 */
export function deserializeHeader(bytes: Uint8Array): {
  ratchetKey: Base64;
  counter: number;
  previousCounter: number;
} {
  let offset = 0;
  let ratchetKey: Base64 | null = null;
  let counter = 0;
  let previousCounter = 0;

  while (offset < bytes.length) {
    // Read field tag
    const { value: tag, bytesRead: tagBytes } = decodeVarint(bytes, offset);
    offset += tagBytes;

    const fieldNumber = tag >>> 3;
    const wireType = tag & 0x07;

    switch (fieldNumber) {
      case 1: {
        // ratchet_key (bytes)
        if (wireType !== WIRE_TYPE_LENGTH_DELIMITED) {
          throw new Error('Invalid wire type for field 1');
        }
        const { value: length, bytesRead: lengthBytes } = decodeVarint(bytes, offset);
        offset += lengthBytes;

        const keyWithPrefix = bytes.slice(offset, offset + length);
        offset += length;

        // Verify and strip DJB prefix
        if (keyWithPrefix.length !== 33 || keyWithPrefix[0] !== DJB_KEY_TYPE) {
          throw new Error('Invalid ratchet key format');
        }
        ratchetKey = bytesToBase64(keyWithPrefix.slice(1));
        break;
      }
      case 2: {
        // counter (uint32)
        if (wireType !== WIRE_TYPE_VARINT) {
          throw new Error('Invalid wire type for field 2');
        }
        const { value, bytesRead: valueBytes } = decodeVarint(bytes, offset);
        offset += valueBytes;
        counter = value;
        break;
      }
      case 3: {
        // previous_counter (uint32)
        if (wireType !== WIRE_TYPE_VARINT) {
          throw new Error('Invalid wire type for field 3');
        }
        const { value, bytesRead: valueBytes } = decodeVarint(bytes, offset);
        offset += valueBytes;
        previousCounter = value;
        break;
      }
      default: {
        offset = skipUnknownField(wireType, bytes, offset);
      }
    }
  }

  if (!ratchetKey) {
    throw new Error('Missing required field: ratchet_key');
  }

  return { ratchetKey, counter, previousCounter };
}

// ============================================================================
// MAC Computation
// ============================================================================

/**
 * Compute message MAC with identity key binding for JSON-format ratchet messages.
 *
 * MAC construction:
 * MAC = HMAC-SHA256(auth_key, version || sender_id || receiver_id || header || ciphertext)[0:8]
 *
 * Identity key binding provides:
 * - Session binding: MAC is only valid for this specific sender-receiver pair
 * - Replay prevention: Message can't be replayed to a different session
 * - Authentication: Verifies sender possesses the chain key
 *
 * @param authKey - Authentication key (32 bytes, from expanded message key)
 * @param senderIdentityKey - Sender's public identity key (32 bytes)
 * @param receiverIdentityKey - Receiver's public identity key (32 bytes)
 * @param serializedHeader - Protobuf-encoded header bytes
 * @param ciphertext - Encrypted message body
 * @returns 8-byte truncated MAC
 *
 * @example
 * ```typescript
 * const mac = computeMessageMac(
 *   authKey,
 *   base64ToBytes(session.localIdentity.x25519PublicKey),
 *   base64ToBytes(session.remoteIdentity.x25519PublicKey),
 *   serializeHeader(ratchetKey, previousCounter, counter),
 *   ciphertextBytes
 * );
 * // mac is 8 bytes
 * ```
 */
export function computeMessageMac(
  authKey: Uint8Array,
  senderIdentityKey: Uint8Array,
  receiverIdentityKey: Uint8Array,
  serializedHeader: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  // Validate inputs
  if (authKey.length !== 32) {
    throw new Error(`Auth key must be 32 bytes, got ${authKey.length}`);
  }
  if (senderIdentityKey.length !== 32) {
    throw new Error(`Sender identity key must be 32 bytes, got ${senderIdentityKey.length}`);
  }
  if (receiverIdentityKey.length !== 32) {
    throw new Error(`Receiver identity key must be 32 bytes, got ${receiverIdentityKey.length}`);
  }

  // Build MAC input: version || sender_identity || receiver_identity || header || ciphertext
  const macInput = concatBytes(
    new Uint8Array([MESSAGE_VERSION_BYTE]),
    senderIdentityKey,
    receiverIdentityKey,
    serializedHeader,
    ciphertext
  );

  // Compute HMAC-SHA256 and truncate to 8 bytes
  const fullMac = hmac(authKey, macInput);
  return fullMac.slice(0, MAC_LENGTH_BYTES);
}

/**
 * Verify message MAC with identity key binding.
 *
 * Uses best-effort full-scan comparison for equal-length MACs.
 *
 * @param authKey - Authentication key (32 bytes)
 * @param senderIdentityKey - Sender's public identity key (32 bytes)
 * @param receiverIdentityKey - Receiver's public identity key (32 bytes)
 * @param serializedHeader - Protobuf-encoded header bytes
 * @param ciphertext - Encrypted message body
 * @param receivedMac - Received MAC to verify (8 bytes)
 * @returns true if MAC is valid
 */
export function verifyMessageMac(
  authKey: Uint8Array,
  senderIdentityKey: Uint8Array,
  receiverIdentityKey: Uint8Array,
  serializedHeader: Uint8Array,
  ciphertext: Uint8Array,
  receivedMac: Uint8Array
): boolean {
  // L2: Compute HMAC even when length is wrong (defense-in-depth)
  // Normalize malformed lengths before the fixed-size comparison. This does
  // not provide a JavaScript constant-time guarantee.
  const expectedMac = computeMessageMac(
    authKey,
    senderIdentityKey,
    receiverIdentityKey,
    serializedHeader,
    ciphertext
  );

  // Truncate expected MAC to MAC_LENGTH_BYTES for comparison
  //
  const expectedTruncated = expectedMac.slice(0, MAC_LENGTH_BYTES);

  // Best-effort full-scan comparison; length mismatch handling is structural.
  return constantTimeEqual(expectedTruncated, receivedMac);
}

// ============================================================================
// Protobuf Wire Format MAC (pinned-reference shape)
// ============================================================================

/**
 * Compute the message MAC using the pinned profile field/input shape.
 *
 * MAC = HMAC-SHA256(macKey, senderIdentity(33) || receiverIdentity(33) || serializedMessage)[0:8]
 *
 * Where serializedMessage = version_byte(1) + protobuf_bytes(N), NOT including the MAC.
 *
 * - Identity keys are 33 bytes (with 0x05 DJB prefix)
 * - Identity keys come before the message
 * - MAC covers version byte + full protobuf
 *
 * @param macKey - MAC key (32 bytes, from expanded message key)
 * @param senderIdentityKey - Sender's public identity key (33 bytes with 0x05 prefix)
 * @param receiverIdentityKey - Receiver's public identity key (33 bytes with 0x05 prefix)
 * @param serializedMessage - version_byte + protobuf_bytes (NOT including MAC)
 * @returns 8-byte truncated MAC
 */
export function computeProtobufMessageMac(
  macKey: Uint8Array,
  senderIdentityKey: Uint8Array,
  receiverIdentityKey: Uint8Array,
  serializedMessage: Uint8Array
): Uint8Array {
  // Validate inputs
  if (macKey.length !== 32) {
    throw new Error(`MAC key must be 32 bytes, got ${macKey.length}`);
  }
  if (senderIdentityKey.length !== 33) {
    throw new Error(
      `Sender identity key must be 33 bytes (with 0x05 prefix), got ${senderIdentityKey.length}`
    );
  }
  if (receiverIdentityKey.length !== 33) {
    throw new Error(
      `Receiver identity key must be 33 bytes (with 0x05 prefix), got ${receiverIdentityKey.length}`
    );
  }

  // Build MAC input: senderIdentity || receiverIdentity || serializedMessage
  //
  const macInput = concatBytes(senderIdentityKey, receiverIdentityKey, serializedMessage);

  // Compute HMAC-SHA256 and truncate to 8 bytes
  const fullMac = hmac(macKey, macInput);
  return fullMac.slice(0, MAC_LENGTH_BYTES);
}

/**
 * Verify a message MAC over the framed protobuf wire fields.
 *
 * Uses best-effort full-scan comparison for equal-length MACs.
 *
 * @param macKey - MAC key (32 bytes, from expanded message key)
 * @param senderIdentityKey - Sender's public identity key (33 bytes with 0x05 prefix)
 * @param receiverIdentityKey - Receiver's public identity key (33 bytes with 0x05 prefix)
 * @param serializedMessage - version_byte + protobuf_bytes (NOT including MAC)
 * @param receivedMac - Received MAC to verify (8 bytes)
 * @returns true if MAC is valid
 */
export function verifyProtobufMessageMac(
  macKey: Uint8Array,
  senderIdentityKey: Uint8Array,
  receiverIdentityKey: Uint8Array,
  serializedMessage: Uint8Array,
  receivedMac: Uint8Array
): boolean {
  // L2: Compute HMAC even when length is wrong (defense-in-depth)
  // Normalize malformed lengths before comparison; no timing guarantee.
  const expectedMac = computeProtobufMessageMac(
    macKey,
    senderIdentityKey,
    receiverIdentityKey,
    serializedMessage
  );

  // Truncate expected MAC to MAC_LENGTH_BYTES for comparison
  const expectedTruncated = expectedMac.slice(0, MAC_LENGTH_BYTES);

  // Best-effort full-scan comparison.
  return constantTimeEqual(expectedTruncated, receivedMac);
}
