/**
 * SignalProtocolMessage / PreKeySignalProtocolMessage Protobuf Encoding/Decoding
 *
 * Encodes and decodes SignalProtocolMessage and PreKeySignalProtocolMessage with protobufjs.
 * These are the core message types of the Signal Protocol's Double Ratchet.
 *
 * Proto schema:
 * ```protobuf
 * message SignalProtocolMessage {
 *   optional bytes  ratchet_key      = 1;
 *   optional uint32 counter          = 2;
 *   optional uint32 previous_counter = 3;
 *   optional bytes  ciphertext       = 4;
 *   optional bytes  pq_ratchet       = 5;
 *   optional bytes  addresses        = 6;
 * }
 *
 * message PreKeySignalProtocolMessage {
 *   optional uint32 pre_key_id        = 1;
 *   optional bytes  base_key          = 2;
 *   optional bytes  identity_key      = 3;
 *   optional bytes  message           = 4;
 *   optional uint32 registration_id   = 5;
 *   optional uint32 signed_pre_key_id = 6;
 *   optional uint32 kyber_pre_key_id  = 7;
 *   optional bytes  kyber_ciphertext  = 8;
 * }
 * ```
 *
 * We extend PreKeySignalProtocolMessage with custom fields at high field numbers
 * (100-102) that do not conflict with the base wire fields. SignalProtocolMessage
 * field 100 authenticates the
 * recipient identity namespace selected by PreKeySignalProtocolMessage field 102.
 *
 * Sender identity belongs to the authenticated transport envelope, not the
 * encrypted PreKeySignalProtocolMessage.
 *
 * The pq_ratchet field (field 5) carries opaque SPQR binary data encoded
 * via encodeSPQRWire/decodeSPQRWire in pq-ratchet-serialize.ts — NOT protobuf.
 *
 * @internal
 */

import protobuf from 'protobufjs';
import type { ProtocolAddress } from '../../../types/address';
import { decodeVarint, encodeVarint } from './primitives';

// ============================================================================
// Protobuf Type Definitions (built programmatically, no .proto file loading)
// ============================================================================
export {};
const root = new protobuf.Root();
// Bound adversarial protobuf work without constraining the documented 10 MiB
// message contract. Larger payloads use the separately bounded attachment path.
export const MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES = 16 * 1024 * 1024;

function assertWireMessageSize(bytes: Uint8Array, label: string): void {
  if (bytes.length > MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES) {
    throw new Error(`${label} exceeds ${MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES}-byte input limit`);
  }
}

/**
 * SignalProtocolMessage protobuf type.
 *
 * Wire fields:
 * - ratchet_key (1, bytes) - current ratchet public key
 * - counter (2, uint32) - message number in current chain
 * - previous_counter (3, uint32) - length of previous sending chain
 * - ciphertext (4, bytes) - encrypted message content
 * - pq_ratchet (5, bytes) - opaque SPQR binary data (NOT protobuf)
 */
const SignalProtocolMessageType = new protobuf.Type('SignalProtocolMessage')
  .add(new protobuf.Field('ratchetKey', 1, 'bytes'))
  .add(new protobuf.Field('counter', 2, 'uint32'))
  .add(new protobuf.Field('previousCounter', 3, 'uint32'))
  .add(new protobuf.Field('ciphertext', 4, 'bytes'))
  .add(new protobuf.Field('pqRatchet', 5, 'bytes'))
  .add(new protobuf.Field('addresses', 6, 'bytes'))
  .add(new protobuf.Field('recipientIdentityType', 100, 'uint32', 'optional'));

const ADDRESS_BINDING_FORMAT_VERSION = 1;

function encodeUint32BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`deviceId must be a uint32, got ${value}`);
  }

  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function readUint32BE(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) {
    throw new Error('Address binding truncated while reading deviceId');
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((total, bytes) => total + bytes.length, 0));
  let offset = 0;
  for (const bytes of arrays) {
    result.set(bytes, offset);
    offset += bytes.length;
  }
  return result;
}

function encodeAddress(address: ProtocolAddress): Uint8Array {
  const userIdBytes = new TextEncoder().encode(address.userId);
  if (userIdBytes.length === 0) {
    throw new Error('Address binding userId cannot be empty');
  }

  return concatBytes(
    encodeVarint(userIdBytes.length),
    userIdBytes,
    encodeUint32BE(address.deviceId)
  );
}

function decodeAddress(
  bytes: Uint8Array,
  offset: number
): { address: ProtocolAddress; offset: number } {
  const { value: userIdLength, bytesRead } = decodeVarint(bytes, offset);
  offset += bytesRead;

  if (userIdLength === 0) {
    throw new Error('Address binding userId cannot be empty');
  }
  if (offset + userIdLength > bytes.length) {
    throw new Error('Address binding truncated while reading userId');
  }

  const userId = new TextDecoder().decode(bytes.slice(offset, offset + userIdLength));
  offset += userIdLength;
  const deviceId = readUint32BE(bytes, offset);
  offset += 4;

  return { address: { userId, deviceId }, offset };
}

/**
 * Serialize sender and recipient addresses for SignalProtocolMessage field 6.
 *
 * ProtocolAddress names are application-defined user IDs, so this package uses
 * a canonical length-delimited UTF-8 representation in the address field.
 */
export function serializeSignalProtocolMessageAddresses(
  senderAddress: ProtocolAddress,
  recipientAddress: ProtocolAddress
): Uint8Array {
  return concatBytes(
    new Uint8Array([ADDRESS_BINDING_FORMAT_VERSION]),
    encodeAddress(senderAddress),
    encodeAddress(recipientAddress)
  );
}

export function deserializeSignalProtocolMessageAddresses(bytes: Uint8Array): {
  senderAddress: ProtocolAddress;
  recipientAddress: ProtocolAddress;
} {
  if (bytes.length === 0) {
    throw new Error('SignalProtocolMessage address binding is missing');
  }
  if (bytes[0] !== ADDRESS_BINDING_FORMAT_VERSION) {
    throw new Error(`Unsupported SignalProtocolMessage address binding version: ${bytes[0]}`);
  }

  let offset = 1;
  const sender = decodeAddress(bytes, offset);
  offset = sender.offset;
  const recipient = decodeAddress(bytes, offset);
  offset = recipient.offset;

  if (offset !== bytes.length) {
    throw new Error('SignalProtocolMessage address binding has trailing bytes');
  }

  return {
    senderAddress: sender.address,
    recipientAddress: recipient.address,
  };
}

export function signalProtocolMessageAddressesEqual(
  encoded: Uint8Array,
  senderAddress: ProtocolAddress,
  recipientAddress: ProtocolAddress
): boolean {
  const decoded = deserializeSignalProtocolMessageAddresses(encoded);
  return (
    decoded.senderAddress.userId === senderAddress.userId &&
    decoded.senderAddress.deviceId === senderAddress.deviceId &&
    decoded.recipientAddress.userId === recipientAddress.userId &&
    decoded.recipientAddress.deviceId === recipientAddress.deviceId
  );
}

/**
 * PreKeySignalProtocolMessage protobuf type.
 *
 * Fields 1-8 are the base PreKeySignalProtocolMessage fields. Fields 100-102 are SDK
 * extensions for KEM one-time prekeys and recipient identity scope.
 */
const PreKeySignalProtocolMessageType = new protobuf.Type('PreKeySignalProtocolMessage')
  // oneTimePreKeyId uses 'optional' rule (proto2 semantics) so that value 0 is
  // distinguished from "not set" using proto2 optional presence.
  // Without this, protobufjs proto3 default behavior omits 0 on encode and
  // makes 0 indistinguishable from absent on decode — breaking X3DH when
  // the one-time prekey has keyId=0.
  .add(new protobuf.Field('oneTimePreKeyId', 1, 'uint32', 'optional'))
  .add(new protobuf.Field('baseKey', 2, 'bytes'))
  .add(new protobuf.Field('identityKey', 3, 'bytes'))
  .add(new protobuf.Field('message', 4, 'bytes'))
  .add(new protobuf.Field('registrationId', 5, 'uint32'))
  .add(new protobuf.Field('signedPreKeyId', 6, 'uint32'))
  // kyberPreKeyId and kemOneTimePreKeyId also use 'optional' for the same reason
  .add(new protobuf.Field('kyberPreKeyId', 7, 'uint32', 'optional'))
  .add(new protobuf.Field('kyberCiphertext', 8, 'bytes'))
  // Custom extension fields (high field numbers to avoid upstream conflicts)
  .add(new protobuf.Field('kemOneTimePreKeyId', 100, 'uint32', 'optional'))
  .add(new protobuf.Field('kemOneTimeCiphertext', 101, 'bytes'))
  .add(new protobuf.Field('recipientIdentityType', 102, 'uint32', 'optional'));

root.add(SignalProtocolMessageType);
root.add(PreKeySignalProtocolMessageType);

// ============================================================================
// SignalProtocolMessage
// ============================================================================

/**
 * SignalProtocolMessage fields for protobuf encoding.
 *
 * Wire fields:
 * - ratchetKey -> ratchet_key (field 1, bytes)
 * - counter -> counter (field 2, uint32)
 * - previousCounter -> previous_counter (field 3, uint32)
 * - ciphertext -> ciphertext (field 4, bytes)
 * - pqRatchet -> pq_ratchet (field 5, bytes) — opaque SPQR binary
 * - addresses -> addresses (field 6, bytes) — sender/recipient address binding
 */
export interface SignalProtocolMessageFields {
  /** Current ratchet public key (field 1) */
  ratchetKey: Uint8Array;
  /** Message number in current sending chain (field 2) */
  counter: number;
  /** Length of previous sending chain (field 3) */
  previousCounter: number;
  /** Encrypted message content (field 4) */
  ciphertext: Uint8Array;
  /** Opaque SPQR binary bytes for post-quantum ratchet state (field 5, optional) */
  pqRatchet?: Uint8Array;
  /** Authenticated sender/recipient ProtocolAddress binding (field 6) */
  addresses: Uint8Array;
  /** ACI=1 or PNI=2 for an enclosing PreKeySignalProtocolMessage (field 100) */
  recipientIdentityType?: number;
}

/**
 * Encode a SignalProtocolMessage to protobuf bytes.
 *
 * Output protobuf fields:
 * [field1: ratchet_key] [field2: counter] [field3: previous_counter]
 * [field4: ciphertext] [field5: pq_ratchet] [field6: addresses]
 *
 * This produces the **protobuf bytes only** — no version byte or MAC.
 * Use `frameSignalProtocolMessage()` from `envelope.ts` for the complete wire format.
 *
 * @param msg - Message fields to encode
 * @returns Protobuf-encoded bytes (no framing)
 *
 */
export function encodeSignalProtocolMessage(msg: SignalProtocolMessageFields): Uint8Array {
  if (!msg.addresses?.length) {
    throw new Error('SignalProtocolMessage addresses field is required');
  }

  const payload: Record<string, unknown> = {
    ratchetKey: msg.ratchetKey,
    counter: msg.counter,
    previousCounter: msg.previousCounter,
    ciphertext: msg.ciphertext,
    addresses: msg.addresses,
  };

  if (msg.pqRatchet !== undefined) {
    payload.pqRatchet = msg.pqRatchet;
  }
  if (msg.recipientIdentityType !== undefined) {
    if (msg.recipientIdentityType !== 1 && msg.recipientIdentityType !== 2) {
      throw new Error('SignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
    }
    payload.recipientIdentityType = msg.recipientIdentityType;
  }

  const message = SignalProtocolMessageType.create(payload);
  return new Uint8Array(SignalProtocolMessageType.encode(message).finish());
}

/**
 * Decode a SignalProtocolMessage from protobuf bytes.
 *
 * Handles unknown fields gracefully (skips them) for forward compatibility.
 * Expects raw protobuf bytes — strip the version byte and MAC first using
 * `parseSignalProtocolMessageEnvelope()` from `envelope.ts`.
 *
 * @param bytes - Protobuf-encoded bytes (no version byte or MAC)
 * @returns Decoded message fields
 */
export function decodeSignalProtocolMessage(bytes: Uint8Array): SignalProtocolMessageFields {
  assertWireMessageSize(bytes, 'SignalProtocolMessage');
  const decoded = SignalProtocolMessageType.decode(bytes);
  const message = SignalProtocolMessageType.toObject(decoded, {
    defaults: false,
    bytes: Uint8Array,
  }) as {
    ratchetKey: Uint8Array;
    counter: number;
    previousCounter: number;
    ciphertext: Uint8Array;
    pqRatchet?: Uint8Array;
    addresses?: Uint8Array;
    recipientIdentityType?: number;
  };

  if (!message.addresses?.length) {
    throw new Error('Missing required field: addresses');
  }
  if (message.ratchetKey?.length !== 33) {
    throw new Error('SignalProtocolMessage ratchetKey must contain exactly 33 bytes');
  }
  if (!message.ciphertext?.length) {
    throw new Error('SignalProtocolMessage ciphertext must not be empty');
  }

  if (
    message.recipientIdentityType !== undefined &&
    message.recipientIdentityType !== 1 &&
    message.recipientIdentityType !== 2
  ) {
    throw new Error('SignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
  }

  return {
    ratchetKey: new Uint8Array(message.ratchetKey),
    counter: message.counter >>> 0,
    previousCounter: message.previousCounter >>> 0,
    ciphertext: new Uint8Array(message.ciphertext),
    pqRatchet: message.pqRatchet?.length ? new Uint8Array(message.pqRatchet) : undefined,
    addresses: new Uint8Array(message.addresses),
    recipientIdentityType: message.recipientIdentityType,
  };
}

// ============================================================================
// PreKeySignalProtocolMessage
// ============================================================================

/**
 * PreKeySignalProtocolMessage fields for protobuf encoding.
 *
 * Maps the base PreKeySignalProtocolMessage fields plus SDK extension fields 100-102.
 *
 * The `message` field (4) carries the **entire framed SignalProtocolMessage** including
 * version byte and MAC.
 *
 * NOTE: TS interface field names use ec/kem naming convention, which differs
 * from the proto wire field names. The encode/decode functions handle the mapping:
 *   ecOneTimePreKeyId      ↔ wire: oneTimePreKeyId (field 1)
 *   ecSignedPreKeyId       ↔ wire: signedPreKeyId (field 6)
 *   kemLastResortPreKeyId  ↔ wire: kyberPreKeyId (field 7)
 *   kemLastResortCiphertext ↔ wire: kyberCiphertext (field 8)
 */
export interface PreKeySignalProtocolMessageFields {
  /** EC one-time prekey ID used for this session (wire: oneTimePreKeyId, field 1, optional) */
  ecOneTimePreKeyId?: number;
  /** Ephemeral base key from the initiator (field 2) */
  baseKey: Uint8Array;
  /** Sender's canonical 67-byte CompositeIdentityV1 (field 3). */
  identityKey: Uint8Array;
  /** Entire framed SignalProtocolMessage: version_byte + protobuf + MAC (field 4) */
  message: Uint8Array;
  /** Sender's registration ID (field 5) */
  registrationId: number;
  /** EC signed prekey ID used for this session (wire: signedPreKeyId, field 6) */
  ecSignedPreKeyId: number;
  /** KEM last-resort prekey ID used for this session (wire: kyberPreKeyId, field 7, optional) */
  kemLastResortPreKeyId?: number;
  /** KEM last-resort encapsulated ciphertext (wire: kyberCiphertext, field 8, optional) */
  kemLastResortCiphertext?: Uint8Array;
  /** KEM one-time prekey ID (field 100, optional — custom extension) */
  kemOneTimePreKeyId?: number;
  /** KEM one-time encapsulated ciphertext (field 101, optional — custom extension) */
  kemOneTimeCiphertext?: Uint8Array;
  /** Recipient identity namespace: ACI=1 or PNI=2 (SDK field 102). */
  recipientIdentityType: number;
}

/**
 * Encode a PreKeySignalProtocolMessage to protobuf bytes.
 *
 * Fields 1-8 are the base protobuf fields; 100-102 are SDK extensions.
 *
 * This produces the **protobuf bytes only** — no version byte.
 * Use `framePreKeySignalProtocolMessage()` from `envelope.ts` for the complete wire format.
 *
 * @param msg - PreKey message fields to encode
 * @returns Protobuf-encoded bytes (no framing)
 *
 */
export function encodePreKeySignalProtocolMessage(msg: PreKeySignalProtocolMessageFields): Uint8Array {
  if (msg.recipientIdentityType !== 1 && msg.recipientIdentityType !== 2) {
    throw new Error('PreKeySignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
  }
  // Map TS interface names → proto wire field names
  const payload: Record<string, unknown> = {
    baseKey: msg.baseKey,
    identityKey: msg.identityKey,
    message: msg.message,
    registrationId: msg.registrationId,
    signedPreKeyId: msg.ecSignedPreKeyId, // TS ecSignedPreKeyId → wire signedPreKeyId
    recipientIdentityType: msg.recipientIdentityType,
  };

  if (msg.ecOneTimePreKeyId !== undefined) {
    payload.oneTimePreKeyId = msg.ecOneTimePreKeyId; // TS ecOneTimePreKeyId → wire oneTimePreKeyId
  }
  if (msg.kemLastResortPreKeyId !== undefined) {
    payload.kyberPreKeyId = msg.kemLastResortPreKeyId; // TS kemLastResortPreKeyId → wire kyberPreKeyId
  }
  if (msg.kemLastResortCiphertext !== undefined) {
    payload.kyberCiphertext = msg.kemLastResortCiphertext; // TS kemLastResortCiphertext → wire kyberCiphertext
  }
  if (msg.kemOneTimePreKeyId !== undefined) {
    payload.kemOneTimePreKeyId = msg.kemOneTimePreKeyId;
  }
  if (msg.kemOneTimeCiphertext !== undefined) {
    payload.kemOneTimeCiphertext = msg.kemOneTimeCiphertext;
  }

  const message = PreKeySignalProtocolMessageType.create(payload);
  return new Uint8Array(PreKeySignalProtocolMessageType.encode(message).finish());
}

/**
 * Decode a PreKeySignalProtocolMessage from protobuf bytes.
 *
 * Handles unknown fields gracefully (skips them) for forward compatibility.
 * Expects raw protobuf bytes — strip the version byte first using
 * `parsePreKeySignalProtocolMessageEnvelope()` from `envelope.ts`.
 *
 * @param bytes - Protobuf-encoded bytes (no version byte)
 * @returns Decoded PreKey message fields
 */
export function decodePreKeySignalProtocolMessage(bytes: Uint8Array): PreKeySignalProtocolMessageFields {
  assertWireMessageSize(bytes, 'PreKeySignalProtocolMessage');
  const decoded = PreKeySignalProtocolMessageType.decode(bytes);
  // Use toObject with defaults:false so that absent optional fields are omitted
  // (undefined) while present fields retain their value — including 0.
  // Proto2 optional presence makes value 0 a valid key ID, distinct
  // from "field not set".
  const wireMessage = PreKeySignalProtocolMessageType.toObject(decoded, {
    defaults: false,
    bytes: Uint8Array,
  }) as {
    oneTimePreKeyId?: number; // wire field 1
    baseKey: Uint8Array; // wire field 2
    identityKey: Uint8Array; // wire field 3
    message: Uint8Array; // wire field 4
    registrationId: number; // wire field 5
    signedPreKeyId: number; // wire field 6
    kyberPreKeyId?: number; // wire field 7
    kyberCiphertext?: Uint8Array; // wire field 8
    kemOneTimePreKeyId?: number; // wire field 100
    kemOneTimeCiphertext?: Uint8Array; // wire field 101
    recipientIdentityType?: number; // wire field 102
  };

  if (wireMessage.baseKey?.length !== 33) {
    throw new Error('PreKeySignalProtocolMessage baseKey must contain exactly 33 bytes');
  }
  if (wireMessage.identityKey?.length !== 67) {
    throw new Error('PreKeySignalProtocolMessage identityKey must contain exactly 67 bytes');
  }
  if (!wireMessage.message?.length) {
    throw new Error('PreKeySignalProtocolMessage message must not be empty');
  }
  if (wireMessage.registrationId === undefined) {
    throw new Error('Missing required field: registrationId');
  }
  if (wireMessage.signedPreKeyId === undefined) {
    throw new Error('Missing required field: signedPreKeyId');
  }
  if (
    wireMessage.recipientIdentityType !== 1 &&
    wireMessage.recipientIdentityType !== 2
  ) {
    throw new Error('PreKeySignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
  }

  // Map proto wire names → TS interface names
  const result: PreKeySignalProtocolMessageFields = {
    baseKey: new Uint8Array(wireMessage.baseKey),
    identityKey: new Uint8Array(wireMessage.identityKey),
    message: new Uint8Array(wireMessage.message),
    registrationId: wireMessage.registrationId >>> 0,
    ecSignedPreKeyId: wireMessage.signedPreKeyId >>> 0, // wire signedPreKeyId → TS ecSignedPreKeyId
    recipientIdentityType: wireMessage.recipientIdentityType,
  };

  // Optional fields: with toObject({defaults:false}), absent fields are undefined
  // and present fields have their value (including 0), preserving proto2
  // optional-field semantics.
  if (wireMessage.oneTimePreKeyId !== undefined) {
    result.ecOneTimePreKeyId = wireMessage.oneTimePreKeyId >>> 0; // wire oneTimePreKeyId → TS ecOneTimePreKeyId
  }
  if (wireMessage.kyberPreKeyId !== undefined) {
    result.kemLastResortPreKeyId = wireMessage.kyberPreKeyId >>> 0; // wire kyberPreKeyId → TS kemLastResortPreKeyId
  }
  if (wireMessage.kyberCiphertext?.length) {
    result.kemLastResortCiphertext = new Uint8Array(wireMessage.kyberCiphertext); // wire kyberCiphertext → TS kemLastResortCiphertext
  }

  // Optional custom extension fields (100-101) — already use correct names
  if (wireMessage.kemOneTimePreKeyId !== undefined) {
    result.kemOneTimePreKeyId = wireMessage.kemOneTimePreKeyId >>> 0;
  }
  if (wireMessage.kemOneTimeCiphertext?.length) {
    result.kemOneTimeCiphertext = new Uint8Array(wireMessage.kemOneTimeCiphertext);
  }

  return result;
}
