/**
 * Sealed Sender Protocol Types
 *
 * TypeScript interfaces for the Sealed Sender protocol: server certificates,
 * sender certificates, unidentified sender messages (V1/V2), seal/unseal
 * options, and protocol constants.
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import type { Base64 } from '../../../types';
import { ContentHint } from '../../../types/messages';

// ============================================================================
// Server Certificate
// ============================================================================

/**
 * Server certificate used to sign sender certificates.
 *
 * Two-layer protobuf structure:
 * - Outer: {certificate bytes, signature}
 * - Inner Certificate: {id, key}
 *
 * Trust chain: trust_root signs certificateBytes.
 *
 */
export {};
export interface ServerCertificate {
  /**
   * Server key identifier.
   * Used for revocation checking and targeted lookup.
   */
  id: number;

  /**
   * Ed25519 public key (32 bytes, base64).
   * Used to verify sender certificate signatures.
   */
  publicKey: Base64;

  /**
   * Protobuf-encoded inner Certificate {id, key}.
   * This is the data that the trust root signs.
   */
  certificateBytes: Base64;

  /**
   * Trust root Ed25519 signature over certificateBytes (64 bytes, base64).
   */
  signature: Base64;
}

// ============================================================================
// Sender Certificate
// ============================================================================

/**
 * Short-lived credential proving sender identity.
 *
 * Two-layer protobuf structure:
 * - Outer: {certificate bytes, signature}
 * - Inner Certificate: {senderE164, senderDevice, expires, identityKey, signer, senderUuid}
 *
 * Trust chain: signer.publicKey signs certificateBytes.
 *
 */
export interface SenderCertificate {
  /**
   * Sender's user identifier (Convex _id).
   */
  senderUuid: string;

  /**
   * Sender's device identifier (1-5).
   */
  senderDeviceId: number;

  /**
   * Sender's X25519 identity public key (32 bytes, base64).
   * Used to verify sender authenticity via Signal Protocol.
   */
  senderIdentityKey: Base64;

  /**
   * Certificate expiration (Unix timestamp in milliseconds).
   * Typically 24 hours from issuance.
   */
  expires: number;

  /**
   * Optional sender phone number (E.164 format).
   * For compatibility with phone-number-based identifiers.
   */
  senderE164?: string;

  /**
   * Embedded server certificate that signed this sender certificate.
   * Contains the full ServerCertificate (id, publicKey, certificateBytes, signature).
   *
   */
  signer: ServerCertificate;

  /**
   * Protobuf-encoded inner Certificate containing all fields + signer bytes.
   * This is the data that signer.publicKey signs.
   */
  certificateBytes: Base64;

  /**
   * Signer's Ed25519 signature over certificateBytes (64 bytes, base64).
   */
  signature: Base64;
}

// ============================================================================
// Delivery Token
// ============================================================================

/**
 * Delivery token for abuse prevention.
 *
 * Derived from recipient's profile key via HKDF.
 * Only contacts who know the profile key can derive the token.
 *
 */
export interface DeliveryToken {
  /**
   * 96-bit token (12 bytes, base64).
   */
  token: Base64;
}

/**
 * Delivery token registration for server storage.
 */
export interface DeliveryTokenRegistration {
  /**
   * User ID this token belongs to.
   */
  userId: string;

  /**
   * SHA-256 hash of the delivery token (base64).
   * Server stores hash, not the token itself.
   */
  tokenHash: Base64;
}

// ============================================================================
// Unidentified Sender Message
// ============================================================================

/**
 * Two-stage sealed-sender message format.
 *
 * Uses two encryption stages:
 * - Stage 1 (Ephemeral): Encrypts sender's identity public key
 * - Stage 2 (Sender): Encrypts certificate + message
 *
 * This provides additional binding between the ephemeral key and sender identity.
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export interface UnidentifiedSenderMessage {
  /**
   * Compound protocol version.
   * Format: (requiredVersion << 4) | currentVersion
   * V1 = 0x11 (requires v1, is v1)
   */
  version: number;

  /**
   * Ephemeral X25519 public key (32 bytes, base64).
   * Used for ECDH key agreement in Stage 1.
   */
  ephemeralPublic: Base64;

  /**
   * Stage 1 encrypted content: sender's identity public key + MAC.
   * Format: AES-CTR(e_cipherKey, senderIdentityPublic) || HMAC(e_macKey, ciphertext)
   * Total: 32 bytes (encrypted key) + 10 bytes (MAC) = 42 bytes
   */
  encryptedStatic: Base64;

  /**
   * Stage 2 encrypted content: certificate + message + MAC.
   * Format: AES-CTR(s_cipherKey, envelope) || HMAC(s_macKey, ciphertext)
   * Where envelope = varint(certLen) || cert || varint(msgLen) || msg || hint || groupId
   */
  encryptedMessage: Base64;
}

/**
 * Decrypted content from sealed sender message.
 */
export interface UnidentifiedSenderMessageContent {
  /**
   * Validated sender certificate.
   */
  senderCertificate: SenderCertificate;

  /**
   * Inner Signal Protocol message (still encrypted with Double Ratchet).
   */
  signalProtocolMessage: Base64;

  /**
   * Content hint for processing.
   */
  contentHint?: ContentHint;

  /**
   * Group ID if this is a group message.
   */
  groupId?: Base64;
}

// ContentHint is imported from ../../types/messages

// ============================================================================
// Sealed Sender Options
// ============================================================================

/**
 * Options for sealing a message.
 */
export interface SealOptions {
  /**
   * Sender's certificate (obtained from server).
   */
  senderCertificate: SenderCertificate;

  /**
   * Sender's X25519 identity private key.
   */
  senderIdentityPrivate: Uint8Array;

  /**
   * Recipient's X25519 identity public key.
   */
  recipientIdentityPublic: Uint8Array;

  /**
   * Signal Protocol message to seal (already encrypted).
   */
  signalProtocolMessage: Uint8Array;

  /**
   * Optional content hint.
   */
  contentHint?: ContentHint;

  /**
   * Optional group ID for group messages.
   */
  groupId?: Uint8Array;
}

/**
 * Options for unsealing a message.
 */
export interface UnsealOptions {
  /**
   * Sealed message to decrypt.
   */
  sealedMessage: UnidentifiedSenderMessage;

  /**
   * Recipient's X25519 identity private key.
   */
  recipientIdentityPrivate: Uint8Array;

  /**
   * Ed25519 trust root public keys for validating server certificates.
   * Server cert signature is verified against these roots.
   *
   */
  trustRoots: Base64[];

  /**
   * Current timestamp for expiration checking.
   * Defaults to Date.now() if not provided.
   */
  currentTime?: number;

  /**
   * Recipient's user identifier for self-send detection.
   * Rejects messages where sender === recipient (replay attack prevention).
   *
   */
  recipientUuid: string;

  /**
   * Recipient's device identifier for self-send detection.
   * Used together with recipientUuid for self-send detection.
   *
   */
  recipientDeviceId: number;
}

// ============================================================================
// Sealed Sender V2 (Multi-Recipient)
// ============================================================================

/**
 * Recipient information for V2 multi-recipient sealed sender.
 *
 * Each recipient receives their own encrypted message key and auth tag,
 * but shares the same message ciphertext.
 *
 */
export interface SealedSenderV2Recipient {
  /**
   * Recipient's service identifier (Convex _id or UUID).
   */
  serviceId: string;

  /**
   * Recipient's device identifier (1-5).
   */
  deviceId: number;

  /**
   * Recipient's registration ID for session validation.
   */
  registrationId: number;

  /**
   * Encrypted message key (M XOR recipient_key).
   * 32 bytes - XOR of random M with HKDF-derived recipient key.
   */
  encryptedMessageKey: Base64;

  /**
   * Per-recipient authentication tag (16 bytes).
   * HKDF output from identity-to-identity ECDH binding sender to message.
   * IKM = identity_agreement || ephemeral_pub || encrypted_key || sender_id_pub || recipient_id_pub
   */
  authenticationTag: Base64;
}

/**
 * V2 multi-recipient sealed sender message format.
 *
 * Uses a multi-recipient KEM based on Barbosa and Farshim's randomness-reuse
 * technique. A single ephemeral key and message
 * ciphertext is shared across all recipients.
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export interface SealedSenderV2Message {
  /**
   * Protocol version.
   * 0x22 = V2 with UUID identifiers
   * 0x23 = V2 with ServiceId
   */
  version: typeof SEALED_SENDER_V2_UUID_VERSION | typeof SEALED_SENDER_V2_SERVICE_ID_VERSION;

  /**
   * Ephemeral X25519 public key (32 bytes, base64).
   * Derived from random M, shared across all recipients.
   */
  ephemeralPublic: Base64;

  /**
   * Per-recipient encrypted key material and auth tags.
   */
  recipients: SealedSenderV2Recipient[];

  /**
   * AES-GCM-SIV encrypted message content.
   * Shared across all recipients - decrypted with key derived from M.
   */
  messageCiphertext: Base64;
}

/**
 * Options for V2 multi-recipient sealing.
 */
export interface SealMultiRecipientOptions {
  /**
   * Sender's certificate (obtained from server).
   */
  senderCertificate: SenderCertificate;

  /**
   * Sender's X25519 identity private key (for auth tag computation).
   */
  senderIdentityPrivate: Uint8Array;

  /**
   * Sender's X25519 identity public key (for auth tag computation).
   */
  senderIdentityPublic: Uint8Array;

  /**
   * Recipients to encrypt for.
   */
  recipients: Array<{
    serviceId: string;
    deviceId: number;
    registrationId: number;
    identityPublic: Uint8Array;
  }>;

  /**
   * Signal Protocol message to seal (already encrypted).
   */
  signalProtocolMessage: Uint8Array;

  /**
   * Optional content hint.
   */
  contentHint?: ContentHint;

  /**
   * Optional group ID for group messages.
   */
  groupId?: Uint8Array;
}

/**
 * Options for V2 unsealing (extends V1 options).
 */
export interface UnsealV2Options {
  /**
   * V2 sealed message to decrypt.
   */
  sealedMessage: SealedSenderV2Message;

  /**
   * Recipient's X25519 identity private key.
   */
  recipientIdentityPrivate: Uint8Array;

  /**
   * Recipient's X25519 identity public key (for auth tag verification).
   */
  recipientIdentityPublic: Uint8Array;

  /**
   * Recipient's service identifier to find their entry.
   */
  recipientServiceId: string;

  /**
   * Recipient's device identifier.
   */
  recipientDeviceId: number;

  /**
   * Ed25519 trust root public keys for validating server certificates.
   *
   */
  trustRoots: Base64[];

  /**
   * Current timestamp for expiration checking.
   */
  currentTime?: number;
}

// ============================================================================
// V2 Constants
// ============================================================================

/**
 * V2 random material size (M) in bytes.
 * Used to derive ephemeral key and symmetric cipher key.
 */
export const V2_RANDOM_M_BYTES = 32;

/**
 * V2 encrypted message key size in bytes.
 * Result of XOR between M and HKDF-derived recipient key.
 */
export const V2_ENCRYPTED_KEY_BYTES = 32;

/**
 * HKDF label for deriving ephemeral private key from random M.
 */
export const V2_LABEL_R = 'Sealed Sender v2: r (2023-08)';

/**
 * HKDF label for deriving symmetric cipher key from random M.
 */
export const V2_LABEL_K = 'Sealed Sender v2: K';

/**
 * HKDF label for deriving per-recipient XOR key.
 * Used in apply_agreement_xor for encrypting M.
 */
export const V2_LABEL_DH = 'Sealed Sender v2: DH';

/**
 * HKDF label for computing per-recipient authentication tag.
 * Uses identity-to-identity ECDH (not ephemeral).
 */
export const V2_LABEL_DH_S = 'Sealed Sender v2: DH-sender';

/**
 * V2 authentication tag length in bytes.
 * HKDF output used directly as auth tag (not HMAC).
 */
export const V2_AUTH_TAG_LEN = 16;

// ============================================================================
// Constants
// ============================================================================

/**
 * Protocol version for sealed sender messages.
 *
 * Signal uses a compound version byte format: (requiredVersion << 4) | currentVersion
 * This allows forward compatibility - a v3 client can decrypt v4 messages if requiredVersion <= 3
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export const SEALED_SENDER_V1_VERSION = 0x11; // Requires v1, is v1 (single recipient)
export const SEALED_SENDER_V2_UUID_VERSION = 0x22; // V2 with UUID identifiers
export const SEALED_SENDER_V2_SERVICE_ID_VERSION = 0x23; // V2 with ServiceId

/** Current version - use V1 for compatibility */
export const SEALED_SENDER_VERSION = SEALED_SENDER_V1_VERSION;

/**
 * Salt used for HKDF key derivation.
 */
export const SEALED_SENDER_SALT = 'UnidentifiedDelivery';

/**
 * Access-key size in bytes (128 bits). The key is derived from AES-GCM
 * ciphertext using a fixed zero nonce.
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export const ACCESS_KEY_BYTES = 16;

/**
 * Certificate expiration duration (24 hours in milliseconds).
 */
export const CERTIFICATE_EXPIRATION_MS = 24 * 60 * 60 * 1000;

/**
 * Ephemeral public key size (X25519).
 */
export const EPHEMERAL_PUBLIC_KEY_BYTES = 32;

/**
 * MAC size (truncated HMAC-SHA256).
 *
 * Sealed-sender MACs are truncated to 10 bytes (80 bits). The Double Ratchet
 * specification Section 8.6 sets the floor at 64 bits;
 * 80 bits is comfortably above this while saving bandwidth.
 */
export const MAC_BYTES = 10;

/**
 * Revoked server certificate IDs.
 *
 * Certificates signed by these server key IDs will be rejected.
 * Empty by default - populated via app releases if a server key is compromised.
 *
 * The reserved example revocation ID is 0xDEADC357.
 *
 */
export const REVOKED_CERTIFICATE_IDS: readonly number[] = [];
