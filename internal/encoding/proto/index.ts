/**
 * Shared Protobuf Module
 *
 * Provides protobuf encoding/decoding for Signal Protocol messages.
 * All wire format encoding uses protobuf — there is no JSON wire format.
 *
 * ## Architecture
 *
 * The protocol uses protobuf for both:
 *
 * 1. **Signing format** — the canonical byte representation that Ed25519
 *    signatures cover. Stable; must never change without a protocol version bump.
 *
 * 2. **Transport format** — how encrypted messages are serialized for delivery
 *    between client and server. Uses protobuf envelope framing (version byte +
 *    protobuf payload + MAC).
 * @internal
 */

// Primitives
export {};
export {
  WIRE_TYPE_VARINT,
  WIRE_TYPE_LENGTH_DELIMITED,
  encodeVarint,
  decodeVarint,
  encodeTag,
  decodeTag,
  encodeUint32Field,
  encodeBytesField,
  skipUnknownField,
  concatFields,
} from './primitives';

// Sender Key Messages
export {
  type SenderKeyMessageFields,
  encodeSenderKeyMessage,
  decodeSenderKeyMessage,
  type SenderKeyDistributionMessageFields,
  encodeSenderKeyDistributionMessage,
  decodeSenderKeyDistributionMessage,
} from './sender-key-message';

// Signal Messages (1:1 session messages)
export {
  type SignalMessageFields,
  encodeSignalMessage,
  decodeSignalMessage,
  serializeSignalMessageAddresses,
  deserializeSignalMessageAddresses,
  signalMessageAddressesEqual,
  type PreKeySignalMessageFields,
  encodePreKeySignalMessage,
  decodePreKeySignalMessage,
} from './signal-message';

// SPQR Wire Format (compact binary, replaces PqRatchetMessage protobuf)
export {
  type SPQRWireMessage,
  encodeSPQRWire,
  decodeSPQRWire,
  encodeVarintLEB128,
  decodeVarintLEB128,
  decodeVarintLEB128Bigint,
  spqrInternalEpochToWireEpoch,
  spqrWireEpochToInternalEpoch,
  spqrWireEpochToBigInt,
} from './pq-ratchet-serialize';

// Envelope Framing (version byte + protobuf + MAC)
export {
  CIPHERTEXT_MESSAGE_CURRENT_VERSION,
  MAC_LENGTH as ENVELOPE_MAC_LENGTH,
  makeVersionByte,
  frameSignalMessage,
  framePreKeySignalMessage,
  parseSignalMessageEnvelope,
  parsePreKeySignalMessageEnvelope,
  getMessageVersion,
} from './envelope';

// SenderKeyMessage Framing (replaces custom EncryptedGroupMessage)
export {
  SENDERKEY_MESSAGE_CURRENT_VERSION,
  frameSenderKeyMessage,
  parseSenderKeyMessage,
} from './sender-key-message';
