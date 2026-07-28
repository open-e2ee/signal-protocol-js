/**
 * Protocol Buffer Bindings for Sealed Sender
 *
 * TypeScript bindings for the sealed sender wire format.
 * Uses protobufjs for encoding/decoding.
 *
 * Field numbers follow the sealed-sender wire format.
 */

import protobuf from 'protobufjs';
import type { Base64 } from '../../../../types';
import { SealedSenderContentType } from '../types';
import { bytesToBase64, base64ToBytes } from '../../../crypto';

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
// Protobuf Root and Type Definitions
// ============================================================================

// Build protobuf types programmatically (avoids file loading issues in RN)
const root = new protobuf.Root();

// ServerCertificate.Certificate — fields match sealed_sender.proto
const ServerCertificateCertificate = new protobuf.Type('Certificate')
  .add(new protobuf.Field('id', 1, 'uint32'))
  .add(new protobuf.Field('key', 2, 'bytes'));

// ServerCertificate (outer wrapper)
const ServerCertificateType = new protobuf.Type('ServerCertificate')
  .add(ServerCertificateCertificate)
  .add(new protobuf.Field('certificate', 1, 'bytes'))
  .add(new protobuf.Field('signature', 2, 'bytes'));

// SenderCertificate.Certificate — field numbers match sealed_sender.proto exactly:
//   senderE164=1, senderDevice=2, expires=3(fixed64), identityKey=4,
//   signer.certificate=5(bytes), senderUuid.uuidString=6
// We only use the embedded certificate variant (field 5) and uuidString (field 6).
const SenderCertificateCertificate = new protobuf.Type('Certificate')
  .add(new protobuf.Field('senderE164', 1, 'string'))
  .add(new protobuf.Field('senderDevice', 2, 'uint32'))
  .add(new protobuf.Field('expires', 3, 'fixed64'))
  .add(new protobuf.Field('identityKey', 4, 'bytes'))
  .add(new protobuf.Field('signerCertificate', 5, 'bytes')) // serialized ServerCertificate
  .add(new protobuf.Field('senderUuid', 6, 'string')); // uuidString variant

// SenderCertificate (outer wrapper)
const SenderCertificateType = new protobuf.Type('SenderCertificate')
  .add(SenderCertificateCertificate)
  .add(new protobuf.Field('certificate', 1, 'bytes'))
  .add(new protobuf.Field('signature', 2, 'bytes'));

// UnidentifiedSenderMessage.Type enum
const MessageTypeEnum = new protobuf.Enum('Type', {
  PREKEY_MESSAGE: 1,
  MESSAGE: 2,
  SENDERKEY_MESSAGE: 7,
  PLAINTEXT_CONTENT: 8,
});

// UnidentifiedSenderMessage.Message
const UnidentifiedSenderMessageMessage = new protobuf.Type('Message')
  .add(MessageTypeEnum)
  .add(new protobuf.Field('type', 1, 'Type'))
  .add(new protobuf.Field('senderCertificate', 2, 'SenderCertificate'))
  .add(new protobuf.Field('content', 3, 'bytes'))
  .add(new protobuf.Field('contentHint', 4, 'uint32'))
  .add(new protobuf.Field('groupId', 5, 'bytes'));

// UnidentifiedSenderMessage
const UnidentifiedSenderMessageType = new protobuf.Type('UnidentifiedSenderMessage')
  .add(MessageTypeEnum)
  .add(UnidentifiedSenderMessageMessage)
  .add(new protobuf.Field('ephemeralPublic', 1, 'bytes'))
  .add(new protobuf.Field('encryptedStatic', 2, 'bytes'))
  .add(new protobuf.Field('encryptedMessage', 3, 'bytes'));

// Add all types to root
root.add(ServerCertificateType);
root.add(SenderCertificateType);
root.add(UnidentifiedSenderMessageType);

// ============================================================================
// Server Certificate Encoding
// ============================================================================

/**
 * Encode server certificate inner Certificate data to protobuf bytes.
 */
export function encodeServerCertificateData(data: ServerCertificateData): Uint8Array {
  const message = ServerCertificateCertificate.create({
    id: data.id,
    key: data.key,
  });
  return ServerCertificateCertificate.encode(message).finish();
}

/**
 * Decode server certificate inner Certificate data from protobuf bytes.
 */
export function decodeServerCertificateData(bytes: Uint8Array): ServerCertificateData {
  const message = ServerCertificateCertificate.decode(bytes) as unknown as {
    id: number;
    key: Uint8Array;
  };
  return {
    id: message.id,
    key: new Uint8Array(message.key),
  };
}

/**
 * Encode server certificate outer wrapper to protobuf bytes.
 */
export function encodeServerCertificate(cert: ServerCertificateProto): Uint8Array {
  const message = ServerCertificateType.create({
    certificate: cert.certificate,
    signature: cert.signature,
  });
  return ServerCertificateType.encode(message).finish();
}

/**
 * Decode server certificate outer wrapper from protobuf bytes.
 */
export function decodeServerCertificate(bytes: Uint8Array): ServerCertificateProto {
  const message = ServerCertificateType.decode(bytes) as unknown as {
    certificate: Uint8Array;
    signature: Uint8Array;
  };
  return {
    certificate: new Uint8Array(message.certificate),
    signature: new Uint8Array(message.signature),
  };
}

// ============================================================================
// Sender Certificate Encoding
// ============================================================================

/**
 * Encode sender certificate inner Certificate data to protobuf bytes.
 * Field numbers are part of the sealed-sender wire format.
 *
 */
export function encodeSenderCertificateData(data: SenderCertificateData): Uint8Array {
  const certData: Record<string, unknown> = {
    senderUuid: data.senderUuid,
    senderDevice: data.senderDevice,
    expires: data.expires,
    identityKey: data.identityKey,
    signerCertificate: data.signerCertificate,
  };

  if (data.senderE164) {
    certData.senderE164 = data.senderE164;
  }

  const message = SenderCertificateCertificate.create(certData);
  return SenderCertificateCertificate.encode(message).finish();
}

/**
 * Decode sender certificate inner Certificate data from protobuf bytes.
 *
 */
export function decodeSenderCertificateData(bytes: Uint8Array): SenderCertificateData {
  const message = SenderCertificateCertificate.decode(bytes) as unknown as {
    senderE164?: string;
    senderUuid: string;
    senderDevice: number;
    expires: number | { low: number; high: number };
    identityKey: Uint8Array;
    signerCertificate?: Uint8Array;
  };

  // Handle protobuf Long type for fixed64 expires
  let expires: number;
  if (typeof message.expires === 'number') {
    expires = message.expires;
  } else if (message.expires && typeof message.expires === 'object') {
    expires = (message.expires.high >>> 0) * 0x100000000 + (message.expires.low >>> 0);
  } else {
    expires = 0;
  }

  return {
    senderE164: message.senderE164 || undefined,
    senderUuid: message.senderUuid,
    senderDevice: message.senderDevice,
    expires,
    identityKey: new Uint8Array(message.identityKey),
    signerCertificate: message.signerCertificate
      ? new Uint8Array(message.signerCertificate)
      : new Uint8Array(0),
  };
}

/**
 * Encode sender certificate outer wrapper to protobuf bytes.
 */
export function encodeSenderCertificate(cert: SenderCertificateProto): Uint8Array {
  const message = SenderCertificateType.create({
    certificate: cert.certificate,
    signature: cert.signature,
  });
  return SenderCertificateType.encode(message).finish();
}

/**
 * Decode sender certificate outer wrapper from protobuf bytes.
 */
export function decodeSenderCertificate(bytes: Uint8Array): SenderCertificateProto {
  const message = SenderCertificateType.decode(bytes) as unknown as {
    certificate: Uint8Array;
    signature: Uint8Array;
  };
  return {
    certificate: new Uint8Array(message.certificate),
    signature: new Uint8Array(message.signature),
  };
}

// ============================================================================
// UnidentifiedSenderMessage Encoding
// ============================================================================

/**
 * Encode inner message data to bytes.
 */
export function encodeUnidentifiedSenderMessageData(
  data: UnidentifiedSenderMessageData
): Uint8Array {
  const msgData: Record<string, unknown> = {
    type: data.type,
    senderCertificate: {
      certificate: data.senderCertificate.certificate,
      signature: data.senderCertificate.signature,
    },
    content: data.content,
  };

  if (data.contentHint !== undefined) {
    msgData.contentHint = data.contentHint;
  }

  if (data.groupId) {
    msgData.groupId = data.groupId;
  }

  const message = UnidentifiedSenderMessageMessage.create(msgData);
  return UnidentifiedSenderMessageMessage.encode(message).finish();
}

/**
 * Decode inner message data from bytes.
 */
export function decodeUnidentifiedSenderMessageData(
  bytes: Uint8Array
): UnidentifiedSenderMessageData {
  const message = UnidentifiedSenderMessageMessage.decode(bytes) as unknown as {
    type: number;
    senderCertificate: {
      certificate: Uint8Array;
      signature: Uint8Array;
    };
    content: Uint8Array;
    contentHint?: number;
    groupId?: Uint8Array;
  };

  return {
    type: message.type as SealedSenderContentType,
    senderCertificate: {
      certificate: new Uint8Array(message.senderCertificate.certificate),
      signature: new Uint8Array(message.senderCertificate.signature),
    },
    content: new Uint8Array(message.content),
    contentHint: message.contentHint,
    groupId: message.groupId ? new Uint8Array(message.groupId) : undefined,
  };
}

/**
 * Encode outer sealed sender message to bytes.
 */
export function encodeUnidentifiedSenderMessage(msg: UnidentifiedSenderMessageProto): Uint8Array {
  const message = UnidentifiedSenderMessageType.create({
    ephemeralPublic: msg.ephemeralPublic,
    encryptedStatic: msg.encryptedStatic,
    encryptedMessage: msg.encryptedMessage,
  });
  return UnidentifiedSenderMessageType.encode(message).finish();
}

/**
 * Decode outer sealed sender message from bytes.
 */
export function decodeUnidentifiedSenderMessage(bytes: Uint8Array): UnidentifiedSenderMessageProto {
  const message = UnidentifiedSenderMessageType.decode(bytes) as unknown as {
    ephemeralPublic: Uint8Array;
    encryptedStatic: Uint8Array;
    encryptedMessage: Uint8Array;
  };

  return {
    ephemeralPublic: new Uint8Array(message.ephemeralPublic),
    encryptedStatic: new Uint8Array(message.encryptedStatic),
    encryptedMessage: new Uint8Array(message.encryptedMessage),
  };
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
