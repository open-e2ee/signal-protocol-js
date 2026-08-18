/**
 * Wire Codec for Sealed Sender
 *
 * Hand-written static encoders and decoders for the sealed sender wire format,
 * built on the shared protobuf primitives. Nothing generates code at runtime, so
 * this path runs under `script-src 'self'`, in a Chrome MV3 extension, and
 * under `node --disallow-code-generation-from-strings`.
 *
 * A certificate signature covers its *serialized* inner bytes, so byte
 * identity here is what keeps an already-issued certificate verifiable. Two
 * consequences run through the whole module:
 *
 * - Nothing re-encodes a signed region. Wherever the surface carries a signed
 *   payload it carries the raw bytes the signer saw. That covers `certificate`
 *   in either wrapper, and `signerCertificate` inside the sender certificate.
 *   The decoders hand those bytes straight through.
 * - The encoders reproduce what this module emitted before, field for field
 *   and byte for byte, including writing an explicitly-set zero. The
 *   `sealed-sender` golden vectors pin every case in both directions. One
 *   input diverges. A string holding an unpaired surrogate encodes to the
 *   replacement character here. Reflection emitted the surrogate's own three
 *   bytes. The `senderE164` and `senderUuid` fields are the only string
 *   fields, and no verification path re-encodes either.
 *
 * Field numbers are those this format has always written, and
 * `UnidentifiedDelivery.proto` alongside this file now records them.
 */

import type { Base64 } from '../../../../types';
import { SealedSenderContentType } from '../types';
/* The encoding helpers come from their own module rather than the crypto
 * barrel. The relay component bundles this codec, and the barrel also exports
 * `generateRandomBytes`, whose third-choice runtime fallback is a dynamic
 * `import('expo-crypto')`. That fallback never runs on a server, but a bundler
 * still parses what it reaches, and the Expo package pulls in React Native. */
import { bytesToBase64, base64ToBytes } from '../../../crypto/utils';
import {
  ProtoReader,
  concatFields,
  encodeBytesField,
  encodeEnumField,
  encodeFixed64Field,
  encodeMessageField,
  encodeStringField,
  encodeUint32Field,
} from '../../../encoding/proto/primitives';

// ============================================================================
// Type Definitions (matching proto messages)
// ============================================================================

/**
 * Server certificate inner Certificate data.
 */
export {};
export interface ServerCertificateData {
  id: number;
  key: Uint8Array;
}

/**
 * Serialized server certificate with signature (outer wrapper).
 */
export interface ServerCertificateProto {
  certificate: Uint8Array;
  signature: Uint8Array;
}

/**
 * Sender certificate inner Certificate data.
 */
export interface SenderCertificateData {
  senderE164?: string;
  senderUuid: string;
  senderDevice: number;
  expires: number;
  identityKey: Uint8Array;
  signerCertificate: Uint8Array; // serialized ServerCertificate proto bytes
}

/**
 * Serialized sender certificate with signature (outer wrapper).
 */
export interface SenderCertificateProto {
  certificate: Uint8Array;
  signature: Uint8Array;
}

/**
 * Message type enum (matches proto).
 *
 * Aliases the implementation's content type so the wire enum and the type the
 * seal/unseal path carries cannot drift apart.
 */
export { SealedSenderContentType as MessageType };

/**
 * Inner message structure.
 */
export interface UnidentifiedSenderMessageData {
  type: SealedSenderContentType;
  senderCertificate: SenderCertificateProto;
  content: Uint8Array;
  contentHint?: number;
  groupId?: Uint8Array;
}

/**
 * Outer sealed sender message.
 */
export interface UnidentifiedSenderMessageProto {
  ephemeralPublic: Uint8Array;
  encryptedStatic: Uint8Array;
  encryptedMessage: Uint8Array;
}

// ============================================================================
// Field Numbers
// ============================================================================

/** `ServerCertificate.Certificate`: the signed inner server certificate. */
const SERVER_CERTIFICATE_DATA = {
  id: 1,
  key: 2,
} as const;

/** `ServerCertificate`: the outer wrapper carrying the signature. */
const SERVER_CERTIFICATE = {
  certificate: 1,
  signature: 2,
} as const;

/** `SenderCertificate.Certificate`: the signed inner sender certificate. */
const SENDER_CERTIFICATE_DATA = {
  senderE164: 1,
  senderDevice: 2,
  expires: 3,
  identityKey: 4,
  signerCertificate: 5,
  senderUuid: 6,
} as const;

/** `SenderCertificate`: the outer wrapper carrying the signature. */
const SENDER_CERTIFICATE = {
  certificate: 1,
  signature: 2,
} as const;

/** `UnidentifiedSenderMessage.Message`: the decrypted inner message. */
const UNIDENTIFIED_SENDER_MESSAGE_DATA = {
  type: 1,
  senderCertificate: 2,
  content: 3,
  contentHint: 4,
  groupId: 5,
} as const;

/** `UnidentifiedSenderMessage`: the sealed envelope. */
const UNIDENTIFIED_SENDER_MESSAGE = {
  ephemeralPublic: 1,
  encryptedStatic: 2,
  encryptedMessage: 3,
} as const;

/** The zero value a bytes field decodes to when the message omits it. */
function emptyBytes(): Uint8Array {
  return new Uint8Array(0);
}

// ============================================================================
// Server Certificate Encoding
// ============================================================================

/**
 * Encode server certificate inner Certificate data to protobuf bytes.
 *
 * These are the bytes the trust root signs.
 */
export function encodeServerCertificateData(data: ServerCertificateData): Uint8Array {
  return concatFields(
    encodeUint32Field(SERVER_CERTIFICATE_DATA.id, data.id),
    encodeBytesField(SERVER_CERTIFICATE_DATA.key, data.key)
  );
}

/**
 * Decode server certificate inner Certificate data from protobuf bytes.
 */
export function decodeServerCertificateData(bytes: Uint8Array): ServerCertificateData {
  const reader = new ProtoReader(bytes);
  let id = 0;
  let key = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SERVER_CERTIFICATE_DATA.id:
        id = reader.readUint32();
        break;
      case SERVER_CERTIFICATE_DATA.key:
        key = reader.readBytes();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return { id, key };
}

/**
 * Encode server certificate outer wrapper to protobuf bytes.
 */
export function encodeServerCertificate(cert: ServerCertificateProto): Uint8Array {
  return concatFields(
    encodeBytesField(SERVER_CERTIFICATE.certificate, cert.certificate),
    encodeBytesField(SERVER_CERTIFICATE.signature, cert.signature)
  );
}

/**
 * Decode server certificate outer wrapper from protobuf bytes.
 *
 * `certificate` comes back exactly as it arrived. It is the byte string that
 * the signature covers.
 */
export function decodeServerCertificate(bytes: Uint8Array): ServerCertificateProto {
  const reader = new ProtoReader(bytes);
  let certificate = emptyBytes();
  let signature = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SERVER_CERTIFICATE.certificate:
        certificate = reader.readBytes();
        break;
      case SERVER_CERTIFICATE.signature:
        signature = reader.readBytes();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return { certificate, signature };
}

// ============================================================================
// Sender Certificate Encoding
// ============================================================================

/**
 * Encode sender certificate inner Certificate data to protobuf bytes.
 * Field numbers are part of the sealed-sender wire format.
 *
 * These are the bytes the issuing server signs. Fields are written in field
 * number order. `senderE164` is written only when the sender has one, which is
 * the one field a certificate may legitimately omit.
 */
export function encodeSenderCertificateData(data: SenderCertificateData): Uint8Array {
  const parts: Uint8Array[] = [];

  if (data.senderE164) {
    parts.push(encodeStringField(SENDER_CERTIFICATE_DATA.senderE164, data.senderE164));
  }

  parts.push(encodeUint32Field(SENDER_CERTIFICATE_DATA.senderDevice, data.senderDevice));
  parts.push(encodeFixed64Field(SENDER_CERTIFICATE_DATA.expires, BigInt(data.expires)));
  parts.push(encodeBytesField(SENDER_CERTIFICATE_DATA.identityKey, data.identityKey));
  parts.push(encodeBytesField(SENDER_CERTIFICATE_DATA.signerCertificate, data.signerCertificate));
  parts.push(encodeStringField(SENDER_CERTIFICATE_DATA.senderUuid, data.senderUuid));

  return concatFields(...parts);
}

/**
 * Decode sender certificate inner Certificate data from protobuf bytes.
 *
 * `signerCertificate` is the serialized `ServerCertificate` and is returned
 * unmodified: the sender certificate's signature covers these bytes, so
 * re-encoding it here would invalidate certificates that are currently valid.
 */
export function decodeSenderCertificateData(bytes: Uint8Array): SenderCertificateData {
  const reader = new ProtoReader(bytes);
  let senderE164 = '';
  let senderUuid = '';
  let senderDevice = 0;
  let expires = 0;
  let identityKey = emptyBytes();
  let signerCertificate = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SENDER_CERTIFICATE_DATA.senderE164:
        senderE164 = reader.readString();
        break;
      case SENDER_CERTIFICATE_DATA.senderDevice:
        senderDevice = reader.readUint32();
        break;
      case SENDER_CERTIFICATE_DATA.expires:
        // Milliseconds since the epoch. A Number holds that exactly well past
        // any expiry a 24-hour credential can carry, and the surface has
        // always been a Number.
        expires = Number(reader.readFixed64());
        break;
      case SENDER_CERTIFICATE_DATA.identityKey:
        identityKey = reader.readBytes();
        break;
      case SENDER_CERTIFICATE_DATA.signerCertificate:
        signerCertificate = reader.readBytes();
        break;
      case SENDER_CERTIFICATE_DATA.senderUuid:
        senderUuid = reader.readString();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return {
    senderE164: senderE164 || undefined,
    senderUuid,
    senderDevice,
    expires,
    identityKey,
    signerCertificate,
  };
}

/**
 * Encode sender certificate outer wrapper to protobuf bytes.
 */
export function encodeSenderCertificate(cert: SenderCertificateProto): Uint8Array {
  return concatFields(
    encodeBytesField(SENDER_CERTIFICATE.certificate, cert.certificate),
    encodeBytesField(SENDER_CERTIFICATE.signature, cert.signature)
  );
}

/**
 * Decode sender certificate outer wrapper from protobuf bytes.
 *
 * `certificate` comes back exactly as it arrived. It is the byte string that
 * the signature covers.
 */
export function decodeSenderCertificate(bytes: Uint8Array): SenderCertificateProto {
  const reader = new ProtoReader(bytes);
  let certificate = emptyBytes();
  let signature = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case SENDER_CERTIFICATE.certificate:
        certificate = reader.readBytes();
        break;
      case SENDER_CERTIFICATE.signature:
        signature = reader.readBytes();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return { certificate, signature };
}

// ============================================================================
// UnidentifiedSenderMessage Encoding
// ============================================================================

/**
 * Encode inner message data to bytes.
 *
 * `contentHint` is written whenever it is set, zero included. An absent hint
 * and a hint of zero are different statements. `groupId` follows the same rule.
 */
export function encodeUnidentifiedSenderMessageData(
  data: UnidentifiedSenderMessageData
): Uint8Array {
  const parts: Uint8Array[] = [
    encodeEnumField(UNIDENTIFIED_SENDER_MESSAGE_DATA.type, data.type),
    encodeMessageField(
      UNIDENTIFIED_SENDER_MESSAGE_DATA.senderCertificate,
      encodeSenderCertificate(data.senderCertificate)
    ),
    encodeBytesField(UNIDENTIFIED_SENDER_MESSAGE_DATA.content, data.content),
  ];

  if (data.contentHint !== undefined) {
    parts.push(encodeUint32Field(UNIDENTIFIED_SENDER_MESSAGE_DATA.contentHint, data.contentHint));
  }

  if (data.groupId) {
    parts.push(encodeBytesField(UNIDENTIFIED_SENDER_MESSAGE_DATA.groupId, data.groupId));
  }

  return concatFields(...parts);
}

/**
 * Decode inner message data from bytes.
 *
 * `type` is returned as it arrived: 0 when the field is absent, and any
 * other value the wire carried, declared by the enum or not. Reflection
 * clamped every undeclared value to the enum's first arm. Both an absent type
 * and a type from a newer peer were reported as `PREKEY_MESSAGE`, which the
 * sender never wrote. Preserving the value is also what the protobuf spec
 * asks of a decoder.
 *
 * The return type names the enum but nothing here narrows to it, so a caller
 * that routes on `type` must put it through `isSealedSenderContentType`
 * first. Neither decrypt path does today. Both read the content type from the
 * envelope framing, not from this decoder.
 */
export function decodeUnidentifiedSenderMessageData(
  bytes: Uint8Array
): UnidentifiedSenderMessageData {
  const reader = new ProtoReader(bytes);
  let type = 0;
  let senderCertificate: SenderCertificateProto = {
    certificate: emptyBytes(),
    signature: emptyBytes(),
  };
  let content = emptyBytes();
  let contentHint = 0;
  let groupId = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case UNIDENTIFIED_SENDER_MESSAGE_DATA.type:
        type = reader.readEnum();
        break;
      case UNIDENTIFIED_SENDER_MESSAGE_DATA.senderCertificate:
        senderCertificate = decodeSenderCertificate(reader.readMessage());
        break;
      case UNIDENTIFIED_SENDER_MESSAGE_DATA.content:
        content = reader.readBytes();
        break;
      case UNIDENTIFIED_SENDER_MESSAGE_DATA.contentHint:
        contentHint = reader.readUint32();
        break;
      case UNIDENTIFIED_SENDER_MESSAGE_DATA.groupId:
        groupId = reader.readBytes();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return {
    type: type as SealedSenderContentType,
    senderCertificate,
    content,
    contentHint,
    groupId,
  };
}

/**
 * Encode outer sealed sender message to bytes.
 */
export function encodeUnidentifiedSenderMessage(msg: UnidentifiedSenderMessageProto): Uint8Array {
  return concatFields(
    encodeBytesField(UNIDENTIFIED_SENDER_MESSAGE.ephemeralPublic, msg.ephemeralPublic),
    encodeBytesField(UNIDENTIFIED_SENDER_MESSAGE.encryptedStatic, msg.encryptedStatic),
    encodeBytesField(UNIDENTIFIED_SENDER_MESSAGE.encryptedMessage, msg.encryptedMessage)
  );
}

/**
 * Decode outer sealed sender message from bytes.
 */
export function decodeUnidentifiedSenderMessage(bytes: Uint8Array): UnidentifiedSenderMessageProto {
  const reader = new ProtoReader(bytes);
  let ephemeralPublic = emptyBytes();
  let encryptedStatic = emptyBytes();
  let encryptedMessage = emptyBytes();

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    switch (fieldNumber) {
      case UNIDENTIFIED_SENDER_MESSAGE.ephemeralPublic:
        ephemeralPublic = reader.readBytes();
        break;
      case UNIDENTIFIED_SENDER_MESSAGE.encryptedStatic:
        encryptedStatic = reader.readBytes();
        break;
      case UNIDENTIFIED_SENDER_MESSAGE.encryptedMessage:
        encryptedMessage = reader.readBytes();
        break;
      default:
        reader.skipField();
        break;
    }
  }

  return { ephemeralPublic, encryptedStatic, encryptedMessage };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert protobuf bytes to Base64.
 */
export function protoToBase64(bytes: Uint8Array): Base64 {
  return bytesToBase64(bytes) as Base64;
}

/**
 * Convert Base64 to protobuf bytes.
 */
export function base64ToProto(base64: Base64): Uint8Array {
  return base64ToBytes(base64);
}
