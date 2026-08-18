/**
 * Envelope Decryption (Unseal) for Sealed Sender
 *
 * Implements two decryption stages:
 * - Stage 1 (Ephemeral): Decrypts sender's identity public key
 * - Stage 2 (Sender): Decrypts certificate + message
 *
 * Security:
 * - MAC is verified BEFORE decryption at each stage (critical for security)
 * - All errors use generic messages to prevent fingerprinting
 * - Constant-time MAC comparison prevents timing attacks
 * - Sender identity is verified against certificate
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import type { UnsealOptions, UnidentifiedSenderMessageContent, SenderCertificate } from './types';
import type { ContentHint } from '../../../types/messages';
import {
  SEALED_SENDER_SALT,
  MAC_BYTES,
  SealedSenderContentType,
  isSealedSenderContentType,
} from './types';
import type { Base64 } from '../../../types';
import { deserializeSenderCertificate, validateSenderCertificate } from './certificate';
import {
  computeSharedSecret,
  hkdf,
  aesCtrDecrypt,
  hmac,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  concatBytes,
  constantTimeEqual,
  secureZeroBytes,
} from '../../crypto';
import { decodeVarint as decodeVarintObj } from '../../encoding/proto/primitives';
import { x25519 } from '@noble/curves/ed25519.js';

/** Generic error message for all unseal failures */
export {};
const GENERIC_ERROR = 'Sealed sender verification failed';

/** contentType(1) + certLen varint(1) + msgLen varint(1) + contentHint(1). */
const MIN_ENVELOPE_BYTES = 4;

/**
 * Decode a varint from bytes, returning a tuple for sealed sender call sites.
 *
 * Wraps the shared decodeVarint primitive with:
 * - Tuple return format [value, bytesRead] (matching sealed sender convention)
 * - Generic error message (no information leakage)
 *
 * @param bytes Bytes to decode from
 * @param offset Starting offset
 * @returns [value, bytesRead]
 */
function decodeVarint(bytes: Uint8Array, offset: number): [number, number] {
  try {
    const { value, bytesRead } = decodeVarintObj(bytes, offset);
    return [value, bytesRead];
  } catch {
    throw new Error(GENERIC_ERROR);
  }
}

/**
 * Parse the decrypted envelope to extract certificate and message.
 *
 * Format: contentType(1) || varint(certLen) || certBytes || varint(msgLen) || msgBytes || contentHint
 *
 * @param envelope Decrypted envelope bytes
 * @returns Parsed envelope components
 */
function parseEnvelope(envelope: Uint8Array): {
  certificate: SenderCertificate;
  message: Uint8Array;
  contentType: SealedSenderContentType;
  contentHint: ContentHint;
} {
  // Smallest well-formed envelope: type, two zero-length varints, hint.
  if (envelope.length < MIN_ENVELOPE_BYTES) {
    throw new Error(GENERIC_ERROR);
  }

  // Read content type (1 byte)
  const contentType = envelope[0];
  if (!isSealedSenderContentType(contentType)) {
    throw new Error(GENERIC_ERROR);
  }
  let offset = 1;

  // Read certificate length
  const [certLen, certLenBytes] = decodeVarint(envelope, offset);
  if (certLenBytes === 0) {
    throw new Error(GENERIC_ERROR);
  }
  offset += certLenBytes;

  // Validate we have enough bytes for certificate
  if (offset + certLen > envelope.length) {
    throw new Error(GENERIC_ERROR);
  }

  // Read certificate bytes
  const certBytes = envelope.slice(offset, offset + certLen);
  offset += certLen;

  // Read message length
  const [msgLen, msgLenBytes] = decodeVarint(envelope, offset);
  if (msgLenBytes === 0) {
    throw new Error(GENERIC_ERROR);
  }
  offset += msgLenBytes;

  // Validate we have enough bytes for message
  if (offset + msgLen > envelope.length) {
    throw new Error(GENERIC_ERROR);
  }

  // Read message bytes
  const message = envelope.slice(offset, offset + msgLen);
  offset += msgLen;

  // Read content hint. The serializer always writes it, and nothing follows
  // it any more, so it is required rather than optional.
  if (offset >= envelope.length) {
    throw new Error(GENERIC_ERROR);
  }
  const contentHint = envelope[offset] as ContentHint;
  offset += 1;

  // The envelope is exactly its fields. Trailing bytes would make the format
  // non-canonical. Two distinct envelopes parsing to the same content.
  if (offset !== envelope.length) {
    throw new Error(GENERIC_ERROR);
  }

  // Deserialize certificate
  const certificate = deserializeSenderCertificate(certBytes);

  return { certificate, message, contentType, contentHint };
}

/**
 * Unseal a Sealed Sender message using two-stage decryption.
 *
 * Reveals the sender identity only after authenticating the encrypted
 * certificate.
 *
 * Two-Stage Algorithm:
 *
 * Stage 1 - Ephemeral Layer (verify and decrypt sender identity):
 * 1. Extract ephemeralPublic, encryptedStatic, encryptedMessage
 * 2. Parse encryptedStatic: e_ciphertext (32 bytes) || e_mac (10 bytes)
 * 3. Compute shared secret: e_ss = X25519(recipientIdentityPrivate, ephemeralPublic)
 * 4. Build salt: e_salt = "UnidentifiedDelivery" || recipientIdentityPublic || ephemeralPublic
 * 5. Derive keys: e_material = HKDF(salt=e_salt, ikm=e_ss, length=96)
 * 6. **VERIFY MAC FIRST**: Compare e_mac with HMAC(e_macKey, e_ciphertext)
 * 7. Decrypt: senderIdentityPublic = AES-CTR(e_cipherKey, iv=0, e_ciphertext)
 *
 * Stage 2 - Sender Layer (verify and decrypt message):
 * 1. Parse encryptedMessage: s_ciphertext || s_mac (10 bytes)
 * 2. Compute shared secret: s_ss = X25519(recipientIdentityPrivate, senderIdentityPublic)
 * 3. Build salt: s_salt = e_chain || e_ciphertext || e_mac
 * 4. Derive keys: s_material = HKDF(salt=s_salt, ikm=s_ss, length=96)
 * 5. **VERIFY MAC FIRST**: Compare s_mac with HMAC(s_macKey, s_ciphertext)
 * 6. Decrypt: envelope = AES-CTR(s_cipherKey, iv=0, s_ciphertext)
 * 7. Parse envelope to extract certificate and message
 * 8. Validate certificate matches decrypted sender identity
 * 9. Validate certificate (expiration, signature, revocation)
 * 10. Self-send detection
 *
 * Security:
 * - MAC is verified BEFORE decryption at each stage
 * - Sender identity from Stage 1 is verified against certificate
 *
 * @param options Unsealing options
 * @returns Decrypted content with validated sender certificate
 * @throws Error (generic) if any validation fails
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export async function unseal(options: UnsealOptions): Promise<UnidentifiedSenderMessageContent> {
  const { sealedMessage, recipientIdentityPrivate, trustRoots, currentTime } = options;

  // Arrays to track for secure zeroing
  const toZero: Uint8Array[] = [];

  // Step 1: Verify version
  // Signal Protocol version format: (requiredVersion << 4) | currentVersion
  const requiredVersion = (sealedMessage.version >> 4) & 0x0f;
  const currentVersion = sealedMessage.version & 0x0f;

  // We support messages that require version 1 or lower
  if (requiredVersion > 1) {
    throw new Error(GENERIC_ERROR);
  }

  // Current version must also be valid (1 for now)
  if (currentVersion < 1) {
    throw new Error(GENERIC_ERROR);
  }

  try {
    // ========================================================================
    // Stage 1: Ephemeral Layer
    // Decrypt sender's identity public key
    // ========================================================================

    // Step 1.1: Extract components
    const ephemeralPublicBytes = base64ToBytes(sealedMessage.ephemeralPublic);
    const encryptedStatic = base64ToBytes(sealedMessage.encryptedStatic);
    const encryptedMessage = base64ToBytes(sealedMessage.encryptedMessage);

    // Validate ephemeral key size
    if (ephemeralPublicBytes.length !== 32) {
      throw new Error(GENERIC_ERROR);
    }

    // Step 1.2: Parse encryptedStatic: e_ciphertext || e_mac
    // e_ciphertext = 32 bytes (encrypted sender identity public key)
    // e_mac = MAC_BYTES
    const expectedStaticLen = 32 + MAC_BYTES;
    if (encryptedStatic.length !== expectedStaticLen) {
      throw new Error(GENERIC_ERROR);
    }
    const e_ciphertext = encryptedStatic.slice(0, 32);
    const e_mac = encryptedStatic.slice(32, 32 + MAC_BYTES);

    // Step 1.3: Compute shared secret: e_ss = ECDH(recipientIdentityPrivate, ephemeralPublic)
    const recipientPrivateBase64 = bytesToBase64(recipientIdentityPrivate) as Base64;
    const ephemeralPublicBase64 = bytesToBase64(ephemeralPublicBytes) as Base64;
    const e_sharedSecret = await computeSharedSecret(recipientPrivateBase64, ephemeralPublicBase64);
    toZero.push(e_sharedSecret);

    // Step 1.4: build the Stage 1 salt.
    // We need the recipient's public key, so derive it from the private key.
    // Note: for X25519, we cannot easily derive public from private without the
    // curve library.
    // The recipient should provide their public key. For now, we will need to
    // add it to options.
    // WORKAROUND: use the certificate's expected sender identity to validate
    // later.
    const saltPrefix = stringToBytes(SEALED_SENDER_SALT);

    // Derive recipient's public key from private key for salt computation.
    // The reference implementation uses the recipient's stored public key. We derive it from the private key.
    const recipientIdentityPublic = x25519.getPublicKey(recipientIdentityPrivate);

    const e_salt = concatBytes(saltPrefix, recipientIdentityPublic, ephemeralPublicBytes);

    // Step 1.5: Derive ephemeral keys (96 bytes: cipher + mac + chain)
    const e_material = await hkdf(e_sharedSecret, e_salt, new Uint8Array(0), 96);
    toZero.push(e_material);
    const e_cipherKey = e_material.slice(0, 32);
    const e_macKey = e_material.slice(32, 64);
    const e_chain = e_material.slice(64, 96);
    toZero.push(e_cipherKey, e_macKey, e_chain);

    // Step 1.6: **VERIFY MAC FIRST** (critical for security)
    const expectedE_mac_full = await hmac(e_macKey, e_ciphertext);
    const expectedE_mac = expectedE_mac_full.slice(0, MAC_BYTES);
    if (!constantTimeEqual(e_mac, expectedE_mac)) {
      throw new Error(GENERIC_ERROR);
    }

    // Step 1.7: Decrypt sender's identity public key
    const e_iv = new Uint8Array(16); // All zeros
    const senderIdentityPublic = aesCtrDecrypt(e_cipherKey, e_iv, e_ciphertext);

    // Validate sender identity key size
    if (senderIdentityPublic.length !== 32) {
      throw new Error(GENERIC_ERROR);
    }

    // ========================================================================
    // Stage 2: Sender Layer
    // Decrypt certificate + message
    // ========================================================================

    // Step 2.1: Parse encryptedMessage: s_ciphertext || s_mac
    if (encryptedMessage.length < MAC_BYTES) {
      throw new Error(GENERIC_ERROR);
    }
    const s_ciphertext = encryptedMessage.slice(0, -MAC_BYTES);
    const s_mac = encryptedMessage.slice(-MAC_BYTES);

    // Step 2.2: Compute shared secret: s_ss = ECDH(recipientIdentityPrivate, senderIdentityPublic)
    const senderIdentityPublicBase64 = bytesToBase64(senderIdentityPublic) as Base64;
    const s_sharedSecret = await computeSharedSecret(
      recipientPrivateBase64,
      senderIdentityPublicBase64
    );
    toZero.push(s_sharedSecret);

    // Step 2.3: Build salt for Stage 2 (chained from Stage 1)
    // s_salt = e_chain || e_ciphertext || e_mac
    const s_salt = concatBytes(e_chain, e_ciphertext, e_mac);

    // Step 2.4: Derive sender keys (96 bytes: discard + cipher + mac)
    // The first 32 bytes of the 96-byte derivation are domain-separated discard
    // material. Cipher and MAC keys occupy the remaining bytes.
    const s_material = await hkdf(s_sharedSecret, s_salt, new Uint8Array(0), 96);
    toZero.push(s_material);
    // s_material[0:32] discarded (mirrors EphemeralKeys structure)
    const s_cipherKey = s_material.slice(32, 64);
    const s_macKey = s_material.slice(64, 96);
    toZero.push(s_cipherKey, s_macKey);

    // Step 2.5: **VERIFY MAC FIRST** (critical for security)
    const expectedS_mac_full = await hmac(s_macKey, s_ciphertext);
    const expectedS_mac = expectedS_mac_full.slice(0, MAC_BYTES);
    if (!constantTimeEqual(s_mac, expectedS_mac)) {
      throw new Error(GENERIC_ERROR);
    }

    // Step 2.6: Decrypt envelope
    const s_iv = new Uint8Array(16); // All zeros
    const envelope = aesCtrDecrypt(s_cipherKey, s_iv, s_ciphertext);

    // Step 2.7: Parse envelope
    const { certificate, message, contentType, contentHint } = parseEnvelope(envelope);

    // Step 2.8: Validate sender identity matches certificate
    const certIdentityKey = base64ToBytes(certificate.senderIdentityKey);
    if (!constantTimeEqual(senderIdentityPublic, certIdentityKey)) {
      throw new Error(GENERIC_ERROR);
    }

    // Step 2.9: Validate certificate
    await validateSenderCertificate(certificate, trustRoots, currentTime);

    // Step 2.10: Self-send detection (SPEC Section 6.6)
    // Reject messages where sender === recipient (replay attack prevention)
    if (
      certificate.senderUuid === options.recipientUuid &&
      certificate.senderDeviceId === options.recipientDeviceId
    ) {
      throw new Error(GENERIC_ERROR);
    }

    // Step 2.11: Return validated content
    return {
      senderCertificate: certificate,
      signalProtocolMessage: bytesToBase64(message) as Base64,
      contentHint,
      contentType,
    };
  } finally {
    // Security: Zero all sensitive key material
    for (const arr of toZero) {
      secureZeroBytes(arr);
    }
  }
}
