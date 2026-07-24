/**
 * Sealed Sender Protocol
 *
 * Provides sender anonymity for Signal Protocol messages.
 * Hides sender identity from the server while preserving
 * recipient verification.
 *
 * @see https://signal.org/blog/sealed-sender/
 *
 * @module sealed-sender
 */

// ============================================================================
// Types
// ============================================================================
export {};
export type {
  // Certificates
  ServerCertificate,
  SenderCertificate,

  // Delivery Tokens
  DeliveryToken,
  DeliveryTokenRegistration,

  // V1 Messages
  UnidentifiedSenderMessage,
  UnidentifiedSenderMessageContent,

  // V1 Options
  SealOptions,
  UnsealOptions,

  // V2 Multi-Recipient Types
  SealedSenderV2Recipient,
  SealedSenderV2Message,
  SealMultiRecipientOptions,
  UnsealV2Options,
} from './types';

// ContentHint is exported from the public package (canonical source)

// ============================================================================
// Constants
// ============================================================================

export {
  // Version constants
  SEALED_SENDER_VERSION,
  SEALED_SENDER_V1_VERSION,
  SEALED_SENDER_V2_UUID_VERSION,
  SEALED_SENDER_V2_SERVICE_ID_VERSION,
  SEALED_SENDER_SALT,
  // Access-key derivation
  ACCESS_KEY_BYTES,
  CERTIFICATE_EXPIRATION_MS,
  EPHEMERAL_PUBLIC_KEY_BYTES,
  MAC_BYTES,
  // Security constants (SPEC Section 6.7)
  REVOKED_CERTIFICATE_IDS,
  // V2 Multi-Recipient constants
  V2_RANDOM_M_BYTES,
  V2_ENCRYPTED_KEY_BYTES,
  V2_LABEL_R,
  V2_LABEL_K,
  V2_LABEL_DH,
  V2_LABEL_DH_S,
  V2_AUTH_TAG_LEN,
} from './types';

// ============================================================================
// Access keys
// ============================================================================

export { deriveAccessKey } from './delivery-token';

// ============================================================================
// Certificate Handling
// ============================================================================

export {
  createServerCertificate,
  createSenderCertificate,
  serializeSenderCertificate,
  deserializeSenderCertificate,
  validateSenderCertificate,
  validateServerCertificate,
} from './certificate';

// ============================================================================
// Encryption (Seal)
// ============================================================================

export { seal } from './encryption';

// ============================================================================
// V2 Multi-Recipient Encryption
// ============================================================================

export { sealMultiRecipient } from './encryption-v2';

// ============================================================================
// Decryption (Unseal)
// ============================================================================

export { unseal } from './decryption';

// ============================================================================
// V2 Multi-Recipient Decryption
// ============================================================================

export { unsealV2 } from './decryption-v2';

// ============================================================================
// V2 Binary Serialization
// ============================================================================

export {
  serializeSentMessage,
  deserializeSentMessage,
  serializeReceivedMessage,
  deserializeReceivedMessage,
} from './v2-binary';

// ============================================================================
// Protocol Buffer serialization
// ============================================================================

export {
  // Type definitions
  type ServerCertificateData,
  type ServerCertificateProto,
  type SenderCertificateData,
  type SenderCertificateProto,
  type UnidentifiedSenderMessageData,
  type UnidentifiedSenderMessageProto,
  MessageType as SealedSenderMessageType,
  // Encoding/decoding functions
  encodeServerCertificateData,
  decodeServerCertificateData,
  encodeServerCertificate,
  decodeServerCertificate,
  encodeSenderCertificateData,
  decodeSenderCertificateData,
  encodeSenderCertificate,
  decodeSenderCertificate,
  encodeUnidentifiedSenderMessageData,
  decodeUnidentifiedSenderMessageData,
  encodeUnidentifiedSenderMessage,
  decodeUnidentifiedSenderMessage,
  // Utility functions
  protoToBase64,
  base64ToProto,
} from './proto';
