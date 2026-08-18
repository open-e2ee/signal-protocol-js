/**
 * Envelope Encryption (Seal) for Sealed Sender
 *
 * Implements two encryption stages:
 * - Stage 1 (Ephemeral): Encrypts sender's identity public key
 * - Stage 2 (Sender): Encrypts certificate + message
 *
 * This provides binding between the ephemeral key and sender identity,
 * so the sender cannot be impersonated even if the ephemeral key
 * is somehow compromised.
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import type { SealOptions, UnidentifiedSenderMessage } from './types';
import type { ContentHint } from '../../../types/messages';
import {
  SEALED_SENDER_VERSION,
  SEALED_SENDER_SALT,
  MAC_BYTES,
  SealedSenderContentType,
} from './types';
import type { Base64 } from '../../../types';
import { serializeSenderCertificate } from './certificate';
import {
  generateECDHKeyPair,
  computeSharedSecret,
  hkdf,
  aesCtrEncrypt,
  hmac,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  concatBytes,
  secureZeroBytes,
} from '../../crypto';
import { encodeVarint } from '../../encoding/proto/primitives';

/**
 * Serialize the envelope plaintext (content type + certificate + message).
 *
 * Format: contentType(1) || varint(certLen) || certBytes || varint(msgLen) || msg || contentHint
 *
 * The content type leads because it is what the recipient needs before it can
 * do anything with the payload. No group identifier is serialized. A group
 * message says only that it is a framed SenderKeyMessage, and the recipient
 * resolves the group from the frame's opaque distribution identifier.
 *
 * @param certBytes Serialized sender certificate
 * @param message Signal Protocol message
 * @param contentType How the recipient should decrypt `message`
 * @param contentHint Optional content hint
 * @returns Serialized envelope
 */
export {};
function serializeEnvelope(
  certBytes: Uint8Array,
  message: Uint8Array,
  contentType: SealedSenderContentType,
  contentHint?: ContentHint
): Uint8Array {
  const parts: Uint8Array[] = [];

  // Content type (1 byte)
  parts.push(new Uint8Array([contentType]));

  // Certificate length as varint
  const certLenVarint = encodeVarint(certBytes.length);
  parts.push(certLenVarint);

  // Certificate bytes
  parts.push(certBytes);

  // Message length as varint
  const msgLenVarint = encodeVarint(message.length);
  parts.push(msgLenVarint);

  // Message bytes
  parts.push(message);

  // Content hint (1 byte, optional - default 0)
  if (contentHint !== undefined) {
    parts.push(new Uint8Array([contentHint]));
  } else {
    parts.push(new Uint8Array([0])); // DEFAULT
  }

  return concatBytes(...parts);
}

/**
 * Seal a Signal Protocol message using two-stage encryption.
 *
 * Hides the sender identity from the relay while allowing the recipient to
 * authenticate the sender.
 *
 * Two-Stage Algorithm:
 *
 * Stage 1 - Ephemeral Layer (binds ephemeral key to recipient):
 * 1. Generate ephemeral X25519 keypair (e_pub, e_priv)
 * 2. Compute shared secret: e_ss = X25519(e_priv, recipientIdentityPublic)
 * 3. Build salt: e_salt = "UnidentifiedDelivery" || recipientIdentityPublic || e_pub
 * 4. Derive keys: e_material = HKDF(salt=e_salt, ikm=e_ss, length=96)
 *    - e_cipherKey = e_material[0:32]
 *    - e_macKey = e_material[32:64]
 *    - e_chain = e_material[64:96] (for stage 2 salt)
 * 5. Encrypt: e_ciphertext = AES-CTR(e_cipherKey, iv=0, senderIdentityPublic)
 * 6. MAC: e_mac = HMAC(e_macKey, e_ciphertext)
 * 7. encryptedStatic = e_ciphertext || e_mac
 *
 * Stage 2 - Sender Layer (binds message to sender identity):
 * 1. Compute shared secret: s_ss = X25519(senderIdentityPrivate, recipientIdentityPublic)
 * 2. Build salt: s_salt = e_chain || e_ciphertext || e_mac
 * 3. Derive keys: s_material = HKDF(salt=s_salt, ikm=s_ss, length=64)
 *    - s_cipherKey = s_material[0:32]
 *    - s_macKey = s_material[32:64]
 * 4. Serialize envelope: type || cert || message || hint
 * 5. Encrypt: s_ciphertext = AES-CTR(s_cipherKey, iv=0, envelope)
 * 6. MAC: s_mac = HMAC(s_macKey, s_ciphertext)
 * 7. encryptedMessage = s_ciphertext || s_mac
 *
 * Security: All sensitive key material is zeroed after use.
 *
 * @param options Sealing options
 * @returns Sealed sender message with two-stage encryption
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export async function seal(options: SealOptions): Promise<UnidentifiedSenderMessage> {
  const {
    senderCertificate,
    senderIdentityPrivate,
    recipientIdentityPublic,
    signalProtocolMessage,
    contentHint,
    contentType = SealedSenderContentType.MESSAGE,
  } = options;

  // Arrays to track for secure zeroing
  const toZero: Uint8Array[] = [];

  try {
    // ========================================================================
    // Stage 1: Ephemeral Layer
    // Encrypts sender's identity public key, bound to ephemeral key
    // ========================================================================

    // Step 1.1: Generate ephemeral X25519 keypair
    const ephemeral = await generateECDHKeyPair();
    const ephemeralPublicBytes = base64ToBytes(ephemeral.publicKey);
    const ephemeralPrivateBytes = base64ToBytes(ephemeral.privateKey);
    toZero.push(ephemeralPrivateBytes);

    // Step 1.2: Compute shared secret: e_ss = ECDH(e_priv, recipientIdentityPublic)
    const recipientPublicBase64 = bytesToBase64(recipientIdentityPublic) as Base64;
    const e_sharedSecret = await computeSharedSecret(ephemeral.privateKey, recipientPublicBase64);
    toZero.push(e_sharedSecret);

    // Step 1.3: Build the stage-one HKDF salt.
    // e_salt = "UnidentifiedDelivery" || recipientIdentityPublic || ephemeralPublic
    const saltPrefix = stringToBytes(SEALED_SENDER_SALT);
    const e_salt = concatBytes(saltPrefix, recipientIdentityPublic, ephemeralPublicBytes);

    // Step 1.4: Derive ephemeral keys (96 bytes: cipher + mac + chain)
    const e_material = await hkdf(e_sharedSecret, e_salt, new Uint8Array(0), 96);
    toZero.push(e_material);
    const e_cipherKey = e_material.slice(0, 32);
    const e_macKey = e_material.slice(32, 64);
    const e_chain = e_material.slice(64, 96);
    toZero.push(e_cipherKey, e_macKey, e_chain);

    // Step 1.5: Encrypt sender's identity public key
    // Get sender identity public key from certificate
    const senderIdentityPublic = base64ToBytes(senderCertificate.senderIdentityKey);
    const e_iv = new Uint8Array(16); // All zeros
    const e_ciphertext = aesCtrEncrypt(e_cipherKey, e_iv, senderIdentityPublic);

    // Step 1.6: Compute MAC over Stage 1 ciphertext
    const e_mac_full = await hmac(e_macKey, e_ciphertext);
    const e_mac = e_mac_full.slice(0, MAC_BYTES);

    // Step 1.7: Combine into encryptedStatic
    const encryptedStatic = concatBytes(e_ciphertext, e_mac);

    // ========================================================================
    // Stage 2: Sender Layer
    // Encrypts certificate + message, bound to sender identity
    // ========================================================================

    // Step 2.1: Compute shared secret: s_ss = ECDH(senderIdentityPrivate, recipientIdentityPublic)
    const senderPrivateBase64 = bytesToBase64(senderIdentityPrivate) as Base64;
    const s_sharedSecret = await computeSharedSecret(senderPrivateBase64, recipientPublicBase64);
    toZero.push(s_sharedSecret);

    // Step 2.2: Build salt for Stage 2 (chained from Stage 1)
    // s_salt = e_chain || e_ciphertext || e_mac
    const s_salt = concatBytes(e_chain, e_ciphertext, e_mac);

    // Step 2.3: Derive sender keys (96 bytes: discard + cipher + mac)
    // The first 32 bytes of the 96-byte derivation are domain-separated discard
    // material. Cipher and MAC keys occupy the remaining bytes.
    const s_material = await hkdf(s_sharedSecret, s_salt, new Uint8Array(0), 96);
    toZero.push(s_material);
    // s_material[0:32] discarded (mirrors EphemeralKeys structure)
    const s_cipherKey = s_material.slice(32, 64);
    const s_macKey = s_material.slice(64, 96);
    toZero.push(s_cipherKey, s_macKey);

    // Step 2.4: Serialize envelope (certificate + message)
    const certBytes = serializeSenderCertificate(senderCertificate);
    const envelope = serializeEnvelope(
      certBytes,
      signalProtocolMessage,
      contentType,
      contentHint
    );

    // Step 2.5: Encrypt envelope
    const s_iv = new Uint8Array(16); // All zeros
    const s_ciphertext = aesCtrEncrypt(s_cipherKey, s_iv, envelope);

    // Step 2.6: Compute MAC over Stage 2 ciphertext
    const s_mac_full = await hmac(s_macKey, s_ciphertext);
    const s_mac = s_mac_full.slice(0, MAC_BYTES);

    // Step 2.7: Combine into encryptedMessage
    const encryptedMessage = concatBytes(s_ciphertext, s_mac);

    // ========================================================================
    // Build final message
    // ========================================================================

    return {
      version: SEALED_SENDER_VERSION,
      ephemeralPublic: ephemeral.publicKey as Base64,
      encryptedStatic: bytesToBase64(encryptedStatic) as Base64,
      encryptedMessage: bytesToBase64(encryptedMessage) as Base64,
    };
  } finally {
    // Security: Zero all sensitive key material
    for (const arr of toZero) {
      secureZeroBytes(arr);
    }
  }
}
