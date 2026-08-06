/**
 * SignalProtocolMessage / PreKeySignalProtocolMessage Protobuf Encoding/Decoding
 *
 * Hand-written static codecs for SignalProtocolMessage and
 * PreKeySignalProtocolMessage, built on the shared wire primitives.
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

import type { ProtocolAddress } from '../../../types/address';
import {
  ProtoReader,
  concatFields,
  decodeVarint,
  encodeBytesField,
  encodeUint32Field,
  encodeVarint,
} from './primitives';

// ============================================================================
// Wire Field Numbers
// ============================================================================
export {};
// Bound adversarial protobuf work without constraining the documented 10 MiB
// message contract. Larger payloads use the separately bounded attachment path.
export const MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES = 16 * 1024 * 1024;

function assertWireMessageSize(bytes: Uint8Array, label: string): void {
  if (bytes.length > MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES) {
    throw new Error(`${label} exceeds ${MAX_SIGNAL_PROTOCOL_WIRE_MESSAGE_BYTES}-byte input limit`);
  }
}

/**
 * SignalProtocolMessage wire field numbers.
 *
 * - ratchet_key (1, bytes) - current ratchet public key
 * - counter (2, uint32) - message number in current chain
 * - previous_counter (3, uint32) - length of previous sending chain
 * - ciphertext (4, bytes) - encrypted message content
 * - pq_ratchet (5, bytes) - opaque SPQR binary data (NOT protobuf)
 * - addresses (6, bytes) - sender/recipient address binding
 * - recipient_identity_type (100, uint32) - SDK extension
 */
const SIGNAL_MESSAGE_FIELD = {
  ratchetKey: 1,
  counter: 2,
  previousCounter: 3,
  ciphertext: 4,
  pqRatchet: 5,
  addresses: 6,
  recipientIdentityType: 100,
} as const;

/**
 * PreKeySignalProtocolMessage wire field numbers.
 *
 * Fields 1-8 are the base PreKeySignalProtocolMessage fields. Fields 100-102
 * are SDK extensions for KEM one-time prekeys and recipient identity scope.
 */
const PREKEY_MESSAGE_FIELD = {
  oneTimePreKeyId: 1,
  baseKey: 2,
  identityKey: 3,
  message: 4,
  registrationId: 5,
  signedPreKeyId: 6,
  kyberPreKeyId: 7,
  kyberCiphertext: 8,
  kemOneTimePreKeyId: 100,
  kemOneTimeCiphertext: 101,
  recipientIdentityType: 102,
} as const;

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
 * Presence, not proto3 defaults, decides what reaches the wire: a field the
 * caller set is written even when it equals the type's zero value, so a
 * counter of 0 and a key id of 0 are distinguishable from absent. Fields are
 * written in ascending field-number order.
 *
 * @param msg - Message fields to encode
 * @returns Protobuf-encoded bytes (no framing)
 *
 */
export function encodeSignalProtocolMessage(msg: SignalProtocolMessageFields): Uint8Array {
  if (!msg.addresses?.length) {
    throw new Error('SignalProtocolMessage addresses field is required');
  }
  if (
    msg.recipientIdentityType !== undefined &&
    msg.recipientIdentityType !== 1 &&
    msg.recipientIdentityType !== 2
  ) {
    throw new Error('SignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
  }

  const fields: Uint8Array[] = [];

  if (msg.ratchetKey !== undefined) {
    fields.push(encodeBytesField(SIGNAL_MESSAGE_FIELD.ratchetKey, msg.ratchetKey));
  }
  if (msg.counter !== undefined) {
    fields.push(encodeUint32Field(SIGNAL_MESSAGE_FIELD.counter, msg.counter));
  }
  if (msg.previousCounter !== undefined) {
    fields.push(encodeUint32Field(SIGNAL_MESSAGE_FIELD.previousCounter, msg.previousCounter));
  }
  if (msg.ciphertext !== undefined) {
    fields.push(encodeBytesField(SIGNAL_MESSAGE_FIELD.ciphertext, msg.ciphertext));
  }
  if (msg.pqRatchet !== undefined) {
    fields.push(encodeBytesField(SIGNAL_MESSAGE_FIELD.pqRatchet, msg.pqRatchet));
  }
  fields.push(encodeBytesField(SIGNAL_MESSAGE_FIELD.addresses, msg.addresses));
  if (msg.recipientIdentityType !== undefined) {
    fields.push(
      encodeUint32Field(SIGNAL_MESSAGE_FIELD.recipientIdentityType, msg.recipientIdentityType)
    );
  }

  return concatFields(...fields);
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

  let ratchetKey: Uint8Array | undefined;
  let counter: number | undefined;
  let previousCounter: number | undefined;
  let ciphertext: Uint8Array | undefined;
  let pqRatchet: Uint8Array | undefined;
  let addresses: Uint8Array | undefined;
  let recipientIdentityType: number | undefined;

  const reader = new ProtoReader(bytes);
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SIGNAL_MESSAGE_FIELD.ratchetKey:
        ratchetKey = reader.readBytes();
        break;
      case SIGNAL_MESSAGE_FIELD.counter:
        counter = reader.readUint32();
        break;
      case SIGNAL_MESSAGE_FIELD.previousCounter:
        previousCounter = reader.readUint32();
        break;
      case SIGNAL_MESSAGE_FIELD.ciphertext:
        ciphertext = reader.readBytes();
        break;
      case SIGNAL_MESSAGE_FIELD.pqRatchet:
        pqRatchet = reader.readBytes();
        break;
      case SIGNAL_MESSAGE_FIELD.addresses:
        addresses = reader.readBytes();
        break;
      case SIGNAL_MESSAGE_FIELD.recipientIdentityType:
        recipientIdentityType = reader.readUint32();
        break;
      default:
        reader.skipField();
    }
  }

  if (!addresses?.length) {
    throw new Error('Missing required field: addresses');
  }
  if (ratchetKey?.length !== 33) {
    throw new Error('SignalProtocolMessage ratchetKey must contain exactly 33 bytes');
  }
  if (!ciphertext?.length) {
    throw new Error('SignalProtocolMessage ciphertext must not be empty');
  }

  if (
    recipientIdentityType !== undefined &&
    recipientIdentityType !== 1 &&
    recipientIdentityType !== 2
  ) {
    throw new Error('SignalProtocolMessage recipientIdentityType must be ACI=1 or PNI=2');
  }

  return {
    ratchetKey,
    counter: counter ?? 0,
    previousCounter: previousCounter ?? 0,
    ciphertext,
    pqRatchet: pqRatchet?.length ? pqRatchet : undefined,
    addresses,
    recipientIdentityType,
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
  const fields: Uint8Array[] = [];

  if (msg.ecOneTimePreKeyId !== undefined) {
    // TS ecOneTimePreKeyId → wire oneTimePreKeyId
    fields.push(encodeUint32Field(PREKEY_MESSAGE_FIELD.oneTimePreKeyId, msg.ecOneTimePreKeyId));
  }
  if (msg.baseKey !== undefined) {
    fields.push(encodeBytesField(PREKEY_MESSAGE_FIELD.baseKey, msg.baseKey));
  }
  if (msg.identityKey !== undefined) {
    fields.push(encodeBytesField(PREKEY_MESSAGE_FIELD.identityKey, msg.identityKey));
  }
  if (msg.message !== undefined) {
    fields.push(encodeBytesField(PREKEY_MESSAGE_FIELD.message, msg.message));
  }
  if (msg.registrationId !== undefined) {
    fields.push(encodeUint32Field(PREKEY_MESSAGE_FIELD.registrationId, msg.registrationId));
  }
  if (msg.ecSignedPreKeyId !== undefined) {
    // TS ecSignedPreKeyId → wire signedPreKeyId
    fields.push(encodeUint32Field(PREKEY_MESSAGE_FIELD.signedPreKeyId, msg.ecSignedPreKeyId));
  }
  if (msg.kemLastResortPreKeyId !== undefined) {
    // TS kemLastResortPreKeyId → wire kyberPreKeyId
    fields.push(encodeUint32Field(PREKEY_MESSAGE_FIELD.kyberPreKeyId, msg.kemLastResortPreKeyId));
  }
  if (msg.kemLastResortCiphertext !== undefined) {
    // TS kemLastResortCiphertext → wire kyberCiphertext
    fields.push(
      encodeBytesField(PREKEY_MESSAGE_FIELD.kyberCiphertext, msg.kemLastResortCiphertext)
    );
  }
  if (msg.kemOneTimePreKeyId !== undefined) {
    fields.push(
      encodeUint32Field(PREKEY_MESSAGE_FIELD.kemOneTimePreKeyId, msg.kemOneTimePreKeyId)
    );
  }
  if (msg.kemOneTimeCiphertext !== undefined) {
    fields.push(
      encodeBytesField(PREKEY_MESSAGE_FIELD.kemOneTimeCiphertext, msg.kemOneTimeCiphertext)
    );
  }
  fields.push(
    encodeUint32Field(PREKEY_MESSAGE_FIELD.recipientIdentityType, msg.recipientIdentityType)
  );

  return concatFields(...fields);
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

  // Every field is tracked by presence, so an absent field stays undefined
  // while a present one keeps its value — including 0. Proto2 optional
  // presence makes value 0 a valid key ID, distinct from "field not set".
  const wireMessage: {
    oneTimePreKeyId?: number; // wire field 1
    baseKey?: Uint8Array; // wire field 2
    identityKey?: Uint8Array; // wire field 3
    message?: Uint8Array; // wire field 4
    registrationId?: number; // wire field 5
    signedPreKeyId?: number; // wire field 6
    kyberPreKeyId?: number; // wire field 7
    kyberCiphertext?: Uint8Array; // wire field 8
    kemOneTimePreKeyId?: number; // wire field 100
    kemOneTimeCiphertext?: Uint8Array; // wire field 101
    recipientIdentityType?: number; // wire field 102
  } = {};

  const reader = new ProtoReader(bytes);
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case PREKEY_MESSAGE_FIELD.oneTimePreKeyId:
        wireMessage.oneTimePreKeyId = reader.readUint32();
        break;
      case PREKEY_MESSAGE_FIELD.baseKey:
        wireMessage.baseKey = reader.readBytes();
        break;
      case PREKEY_MESSAGE_FIELD.identityKey:
        wireMessage.identityKey = reader.readBytes();
        break;
      case PREKEY_MESSAGE_FIELD.message:
        wireMessage.message = reader.readBytes();
        break;
      case PREKEY_MESSAGE_FIELD.registrationId:
        wireMessage.registrationId = reader.readUint32();
        break;
      case PREKEY_MESSAGE_FIELD.signedPreKeyId:
        wireMessage.signedPreKeyId = reader.readUint32();
        break;
      case PREKEY_MESSAGE_FIELD.kyberPreKeyId:
        wireMessage.kyberPreKeyId = reader.readUint32();
        break;
      case PREKEY_MESSAGE_FIELD.kyberCiphertext:
        wireMessage.kyberCiphertext = reader.readBytes();
        break;
      case PREKEY_MESSAGE_FIELD.kemOneTimePreKeyId:
        wireMessage.kemOneTimePreKeyId = reader.readUint32();
        break;
      case PREKEY_MESSAGE_FIELD.kemOneTimeCiphertext:
        wireMessage.kemOneTimeCiphertext = reader.readBytes();
        break;
      case PREKEY_MESSAGE_FIELD.recipientIdentityType:
        wireMessage.recipientIdentityType = reader.readUint32();
        break;
      default:
        reader.skipField();
    }
  }

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
    baseKey: wireMessage.baseKey,
    identityKey: wireMessage.identityKey,
    message: wireMessage.message,
    registrationId: wireMessage.registrationId,
    ecSignedPreKeyId: wireMessage.signedPreKeyId, // wire signedPreKeyId → TS ecSignedPreKeyId
    recipientIdentityType: wireMessage.recipientIdentityType,
  };

  // Optional fields: an absent field is undefined and a present one has its
  // value (including 0), preserving proto2 optional-field semantics.
  if (wireMessage.oneTimePreKeyId !== undefined) {
    result.ecOneTimePreKeyId = wireMessage.oneTimePreKeyId; // wire oneTimePreKeyId → TS ecOneTimePreKeyId
  }
  if (wireMessage.kyberPreKeyId !== undefined) {
    result.kemLastResortPreKeyId = wireMessage.kyberPreKeyId; // wire kyberPreKeyId → TS kemLastResortPreKeyId
  }
  if (wireMessage.kyberCiphertext?.length) {
    result.kemLastResortCiphertext = wireMessage.kyberCiphertext; // wire kyberCiphertext → TS kemLastResortCiphertext
  }

  // Optional custom extension fields (100-101) — already use correct names
  if (wireMessage.kemOneTimePreKeyId !== undefined) {
    result.kemOneTimePreKeyId = wireMessage.kemOneTimePreKeyId;
  }
  if (wireMessage.kemOneTimeCiphertext?.length) {
    result.kemOneTimeCiphertext = wireMessage.kemOneTimeCiphertext;
  }

  return result;
}
