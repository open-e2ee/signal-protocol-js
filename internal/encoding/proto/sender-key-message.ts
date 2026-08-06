/**
 * SenderKeyMessage Protobuf Encoding/Decoding
 *
 * Hand-written static codecs for SenderKeyMessage and
 * SenderKeyDistributionMessage, built on the shared wire primitives.
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

import { ProtoReader, concatFields, encodeBytesField, encodeUint32Field } from './primitives';

// ============================================================================
// Wire Field Numbers
// ============================================================================
export {};

/**
 * Both schemas share field numbers 1-3. Field 4 is the ciphertext in
 * SenderKeyMessage and the chain key in SenderKeyDistributionMessage, which
 * alone carries a field 5.
 */
const SENDER_KEY_FIELD = {
  distributionUuid: 1,
  chainId: 2,
  iteration: 3,
  ciphertext: 4,
  chainKey: 4,
  signingKey: 5,
} as const;

/**
 * Return a decoded field's value, or report which required field the wire
 * bytes left out.
 */
function requireDecoded<T>(value: T | undefined, field: string, typeName: string): T {
  if (value === undefined) {
    throw new Error(`Malformed ${typeName}: missing ${field}`);
  }
  return value;
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
 * Optional fields (distributionUuid) are omitted when undefined; presence, not
 * value, decides, so a field the caller set is written even when it is zero.
 *
 * @param msg - Message fields to encode
 * @returns Protobuf-encoded bytes
 */
export function encodeSenderKeyMessage(msg: SenderKeyMessageFields): Uint8Array {
  const fields: Uint8Array[] = [];

  if (msg.distributionUuid !== undefined) {
    fields.push(encodeBytesField(SENDER_KEY_FIELD.distributionUuid, msg.distributionUuid));
  }
  if (msg.chainId !== undefined) {
    fields.push(encodeUint32Field(SENDER_KEY_FIELD.chainId, msg.chainId));
  }
  fields.push(encodeUint32Field(SENDER_KEY_FIELD.iteration, msg.iteration));
  fields.push(encodeBytesField(SENDER_KEY_FIELD.ciphertext, msg.ciphertext));

  return concatFields(...fields);
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
  let distributionUuid: Uint8Array | undefined;
  let chainId: number | undefined;
  let iteration: number | undefined;
  let ciphertext: Uint8Array | undefined;

  const reader = new ProtoReader(bytes);
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SENDER_KEY_FIELD.distributionUuid:
        distributionUuid = reader.readBytes();
        break;
      case SENDER_KEY_FIELD.chainId:
        chainId = reader.readUint32();
        break;
      case SENDER_KEY_FIELD.iteration:
        iteration = reader.readUint32();
        break;
      case SENDER_KEY_FIELD.ciphertext:
        ciphertext = reader.readBytes();
        break;
      default:
        reader.skipField();
    }
  }

  return {
    distributionUuid: distributionUuid?.length ? distributionUuid : undefined,
    chainId,
    iteration: requireDecoded(iteration, 'iteration', 'SenderKeyMessage'),
    ciphertext: requireDecoded(ciphertext, 'ciphertext', 'SenderKeyMessage'),
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
  const fields: Uint8Array[] = [];

  if (msg.distributionUuid !== undefined) {
    fields.push(encodeBytesField(SENDER_KEY_FIELD.distributionUuid, msg.distributionUuid));
  }
  if (msg.chainId !== undefined) {
    fields.push(encodeUint32Field(SENDER_KEY_FIELD.chainId, msg.chainId));
  }
  fields.push(encodeUint32Field(SENDER_KEY_FIELD.iteration, msg.iteration));
  fields.push(encodeBytesField(SENDER_KEY_FIELD.chainKey, msg.chainKey));
  fields.push(encodeBytesField(SENDER_KEY_FIELD.signingKey, msg.signingKey));

  return concatFields(...fields);
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
  let distributionUuid: Uint8Array | undefined;
  let chainId: number | undefined;
  let iteration: number | undefined;
  let chainKey: Uint8Array | undefined;
  let signingKey: Uint8Array | undefined;

  const reader = new ProtoReader(bytes);
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SENDER_KEY_FIELD.distributionUuid:
        distributionUuid = reader.readBytes();
        break;
      case SENDER_KEY_FIELD.chainId:
        chainId = reader.readUint32();
        break;
      case SENDER_KEY_FIELD.iteration:
        iteration = reader.readUint32();
        break;
      case SENDER_KEY_FIELD.chainKey:
        chainKey = reader.readBytes();
        break;
      case SENDER_KEY_FIELD.signingKey:
        signingKey = reader.readBytes();
        break;
      default:
        reader.skipField();
    }
  }

  return {
    distributionUuid: distributionUuid?.length ? distributionUuid : undefined,
    chainId,
    iteration: requireDecoded(iteration, 'iteration', 'SenderKeyDistributionMessage'),
    chainKey: requireDecoded(chainKey, 'chainKey', 'SenderKeyDistributionMessage'),
    signingKey: requireDecoded(signingKey, 'signingKey', 'SenderKeyDistributionMessage'),
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
