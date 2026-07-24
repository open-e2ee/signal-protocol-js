/**
 * SenderKeyMessage Protobuf Encoding/Decoding
 *
 * Encodes and decodes SenderKeyMessage and SenderKeyDistributionMessage with
 * protobufjs.
 *
 * This is the canonical signing format: Ed25519 signatures cover
 * `version_byte + protobuf_encode(SenderKeyMessage)`.
 *
 * Proto schema:
 * ```protobuf
 * message SenderKeyMessage {
 *   optional bytes  distribution_uuid = 1;
 *   optional uint32 chain_id          = 2;
 *   optional uint32 iteration         = 3;
 *   optional bytes  ciphertext        = 4;
 * }
 *
 * message SenderKeyDistributionMessage {
 *   optional bytes  distribution_uuid = 1;
 *   optional uint32 chain_id          = 2;
 *   optional uint32 iteration         = 3;
 *   optional bytes  chain_key         = 4;
 *   optional bytes  signing_key       = 5;
 * }
 * ```
 *
 * ## Current Usage
 *
 * These schemas are used today for the **signing format** — the bytes that
 * Ed25519 covers in `serializeForSigning` (sender-keys/manager.ts).
 *
 * ## Future Usage
 *
 * When switching transport from JSON to protobuf, the same schemas will also
 * encode/decode the **transport format**. The signing format stays unchanged,
 * so no signatures break during the transition. See proto/index.ts for the
 * full transition plan.
 *
 * @internal
 */

import protobuf from 'protobufjs';

// ============================================================================
// Protobuf Type Definitions (built programmatically, no .proto file loading)
// ============================================================================
export {};
const root = new protobuf.Root();

const SenderKeyMessageType = new protobuf.Type('SenderKeyMessage')
  .add(new protobuf.Field('distributionUuid', 1, 'bytes'))
  .add(new protobuf.Field('chainId', 2, 'uint32'))
  .add(new protobuf.Field('iteration', 3, 'uint32'))
  .add(new protobuf.Field('ciphertext', 4, 'bytes'));

const SenderKeyDistributionMessageType = new protobuf.Type('SenderKeyDistributionMessage')
  .add(new protobuf.Field('distributionUuid', 1, 'bytes'))
  .add(new protobuf.Field('chainId', 2, 'uint32'))
  .add(new protobuf.Field('iteration', 3, 'uint32'))
  .add(new protobuf.Field('chainKey', 4, 'bytes'))
  .add(new protobuf.Field('signingKey', 5, 'bytes'));

root.add(SenderKeyMessageType);
root.add(SenderKeyDistributionMessageType);

type DecodedMessage = protobuf.Message<Record<string, unknown>> & Record<string, unknown>;

function hasDecodedField(message: DecodedMessage, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(message, field);
}

function requireDecodedUint32(message: DecodedMessage, field: string, typeName: string): number {
  if (!hasDecodedField(message, field)) {
    throw new Error(`Malformed ${typeName}: missing ${field}`);
  }

  const value = message[field];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`Malformed ${typeName}: invalid ${field}`);
  }

  return value >>> 0;
}

function requireDecodedBytes(message: DecodedMessage, field: string, typeName: string): Uint8Array {
  if (!hasDecodedField(message, field)) {
    throw new Error(`Malformed ${typeName}: missing ${field}`);
  }

  const value = message[field];
  if (!(value instanceof Uint8Array)) {
    throw new Error(`Malformed ${typeName}: invalid ${field}`);
  }

  return new Uint8Array(value);
}

function optionalDecodedUint32(
  message: DecodedMessage,
  field: string,
  typeName: string
): number | undefined {
  return hasDecodedField(message, field)
    ? requireDecodedUint32(message, field, typeName)
    : undefined;
}

function optionalDecodedBytes(
  message: DecodedMessage,
  field: string,
  typeName: string
): Uint8Array | undefined {
  return hasDecodedField(message, field)
    ? requireDecodedBytes(message, field, typeName)
    : undefined;
}

// ============================================================================
// SenderKeyMessage
// ============================================================================

/**
 * SenderKeyMessage fields for protobuf encoding.
 *
 * Wire fields:
 * - distributionUuid → distribution_uuid (field 1, bytes)
 * - chainId → chain_id (field 2, uint32)
 * - iteration → iteration (field 3, uint32)
 * - ciphertext → ciphertext (field 4, bytes)
 */
export interface SenderKeyMessageFields {
  /** Distribution UUID / sender key ID (field 1, optional) */
  distributionUuid?: Uint8Array;
  /** Chain identifier derived from sender key ID (field 2, optional) */
  chainId?: number;
  /** Chain iteration / message index (field 3) */
  iteration: number;
  /** Encrypted message content (field 4) */
  ciphertext: Uint8Array;
}

/**
 * Encode a SenderKeyMessage to protobuf bytes.
 *
 * Output protobuf fields:
 * [field1: distribution_uuid] [field3: iteration] [field4: ciphertext]
 *
 * Fields are encoded in field-number order per protobuf convention.
 * Optional fields (distributionUuid) are omitted when undefined.
 *
 * @param msg - Message fields to encode
 * @returns Protobuf-encoded bytes
 */
export function encodeSenderKeyMessage(msg: SenderKeyMessageFields): Uint8Array {
  const payload: Record<string, unknown> = {
    iteration: msg.iteration,
    ciphertext: msg.ciphertext,
  };

  if (msg.distributionUuid !== undefined) {
    payload.distributionUuid = msg.distributionUuid;
  }

  if (msg.chainId !== undefined) {
    payload.chainId = msg.chainId;
  }

  const message = SenderKeyMessageType.create(payload);
  return new Uint8Array(SenderKeyMessageType.encode(message).finish());
}

/**
 * Decode a SenderKeyMessage from protobuf bytes.
 *
 * Handles unknown fields gracefully (skips them) for forward compatibility.
 *
 * @param bytes - Protobuf-encoded bytes
 * @returns Decoded message fields
 */
export function decodeSenderKeyMessage(bytes: Uint8Array): SenderKeyMessageFields {
  const message = SenderKeyMessageType.decode(bytes) as DecodedMessage;
  const distributionUuid = optionalDecodedBytes(message, 'distributionUuid', 'SenderKeyMessage');

  return {
    distributionUuid: distributionUuid?.length ? distributionUuid : undefined,
    chainId: optionalDecodedUint32(message, 'chainId', 'SenderKeyMessage'),
    iteration: requireDecodedUint32(message, 'iteration', 'SenderKeyMessage'),
    ciphertext: requireDecodedBytes(message, 'ciphertext', 'SenderKeyMessage'),
  };
}

// ============================================================================
// SenderKeyDistributionMessage
// ============================================================================

/**
 * SenderKeyDistributionMessage fields for protobuf encoding.
 *
 * Wire fields:
 * - distributionUuid → distribution_uuid (field 1, bytes)
 * - chainId → chain_id (field 2, uint32)
 * - iteration → iteration (field 3, uint32)
 * - chainKey → chain_key (field 4, bytes)
 * - signingKey → signing_key (field 5, bytes)
 */
export interface SenderKeyDistributionMessageFields {
  /** Distribution UUID / sender key ID (field 1, optional) */
  distributionUuid?: Uint8Array;
  /** Chain identifier derived from sender key ID (field 2, optional) */
  chainId?: number;
  /** Chain iteration / initial chain index (field 3) */
  iteration: number;
  /** Chain key seed (field 4) */
  chainKey: Uint8Array;
  /** Ed25519 public signing key (field 5) */
  signingKey: Uint8Array;
}

/**
 * Encode a SenderKeyDistributionMessage to protobuf bytes.
 *
 * @param msg - Distribution message fields to encode
 * @returns Protobuf-encoded bytes
 */
export function encodeSenderKeyDistributionMessage(
  msg: SenderKeyDistributionMessageFields
): Uint8Array {
  const payload: Record<string, unknown> = {
    iteration: msg.iteration,
    chainKey: msg.chainKey,
    signingKey: msg.signingKey,
  };

  if (msg.distributionUuid !== undefined) {
    payload.distributionUuid = msg.distributionUuid;
  }

  if (msg.chainId !== undefined) {
    payload.chainId = msg.chainId;
  }

  const message = SenderKeyDistributionMessageType.create(payload);
  return new Uint8Array(SenderKeyDistributionMessageType.encode(message).finish());
}

/**
 * Decode a SenderKeyDistributionMessage from protobuf bytes.
 *
 * @param bytes - Protobuf-encoded bytes
 * @returns Decoded distribution message fields
 */
export function decodeSenderKeyDistributionMessage(
  bytes: Uint8Array
): SenderKeyDistributionMessageFields {
  const message = SenderKeyDistributionMessageType.decode(bytes) as DecodedMessage;
  const distributionUuid = optionalDecodedBytes(
    message,
    'distributionUuid',
    'SenderKeyDistributionMessage'
  );

  return {
    distributionUuid: distributionUuid?.length ? distributionUuid : undefined,
    chainId: optionalDecodedUint32(message, 'chainId', 'SenderKeyDistributionMessage'),
    iteration: requireDecodedUint32(message, 'iteration', 'SenderKeyDistributionMessage'),
    chainKey: requireDecodedBytes(message, 'chainKey', 'SenderKeyDistributionMessage'),
    signingKey: requireDecodedBytes(message, 'signingKey', 'SenderKeyDistributionMessage'),
  };
}

// ============================================================================
// SenderKeyMessage Framing
// ============================================================================

/**
 * SenderKeyMessage wire format version.
 * Encodes `(CURRENT_VERSION << 4) | CURRENT_VERSION`, where
 * CURRENT_VERSION is 3.
 */
export const SENDERKEY_MESSAGE_CURRENT_VERSION = 3;

/** Ed25519 signature length in bytes */
const SIGNATURE_LEN = 64;

/**
 * Frame a SenderKeyMessage for transport.
 *
 * Wire format: [version_byte(1)] [protobuf(N)] [signature(64)]
 * @param protobufBytes - Encoded SenderKeyMessage protobuf
 * @param signature - 64-byte Ed25519 signature over [version_byte + protobufBytes]
 * @returns Framed SenderKeyMessage bytes
 */
export function frameSenderKeyMessage(
  protobufBytes: Uint8Array,
  signature: Uint8Array
): Uint8Array {
  if (signature.length !== SIGNATURE_LEN) {
    throw new Error(`Expected ${SIGNATURE_LEN}-byte signature, got ${signature.length}`);
  }
  const versionByte = (SENDERKEY_MESSAGE_CURRENT_VERSION << 4) | SENDERKEY_MESSAGE_CURRENT_VERSION;
  const result = new Uint8Array(1 + protobufBytes.length + signature.length);
  result[0] = versionByte;
  result.set(protobufBytes, 1);
  result.set(signature, 1 + protobufBytes.length);
  return result;
}

/**
 * Parse a framed SenderKeyMessage.
 *
 * Wire format: [version_byte(1)] [protobuf(N)] [signature(64)]
 * @param bytes - Framed SenderKeyMessage bytes
 * @returns Parsed components: version, protobuf bytes, signature
 */
export function parseSenderKeyMessage(bytes: Uint8Array): {
  version: number;
  protobufBytes: Uint8Array;
  signature: Uint8Array;
} {
  if (bytes.length < 1 + SIGNATURE_LEN + 1) {
    throw new Error(
      `SenderKeyMessage too short: ${bytes.length} bytes (minimum ${1 + SIGNATURE_LEN + 1})`
    );
  }
  const version = bytes[0] >> 4;
  return {
    version,
    protobufBytes: bytes.slice(1, bytes.length - SIGNATURE_LEN),
    signature: bytes.slice(bytes.length - SIGNATURE_LEN),
  };
}
