/**
 * Sealed Sender V2 Multi-Recipient Decryption
 *
 * Implements V2 multi-recipient sealed-sender decryption.
 *
 * Algorithm:
 * 1. Parse version, find my recipient entry by serviceId
 * 2. M = apply_agreement_xor(recipient_identity, ephemeral_pub, encrypted_key)
 * 3. Verify E_pub matches X25519(derive_private_from_M(M)) - authenticates XOR decryption
 * 4. K = HKDF(M, LABEL_K)
 * 5. usmc = AES-GCM-SIV.Decrypt(K, nonce=zeros, ciphertext) - authenticated decryption
 * 6. Parse certificate from usmc to get sender identity
 * 7. Verify auth_tag using identity-to-identity ECDH (binds sender to message)
 * 8. Validate sender certificate, return content
 *
 * IMPORTANT: Auth tag is verified AFTER decryption because it requires sender identity
 * from the certificate. This is safe because:
 * - AES-GCM-SIV provides authenticated encryption
 * - Ephemeral key consistency check authenticates the XOR decryption
 * - Auth tag binds the sender's identity to the message
 *
 */

import type { UnsealV2Options, UnidentifiedSenderMessageContent, SenderCertificate } from './types';
import type { ContentHint } from '../../../types/messages';
import { SEALED_SENDER_V2_UUID_VERSION, SEALED_SENDER_V2_SERVICE_ID_VERSION } from './types';
import type { Base64 } from '../../../types';
import { deserializeSenderCertificate, validateSenderCertificate } from './certificate';
import {
  deriveEphemeralPrivateFromM,
  deriveCipherKeyFromM,
  applyAgreementXor,
  computeAuthenticationTag,
  verifyAuthenticationTag,
} from './v2-helpers';
import {
  bytesToBase64,
  base64ToBytes,
  constantTimeEqual,
  secureZeroBytes,
  aesGcmSivDecryptZeroNonce,
} from '../../crypto';
import { decodeVarint } from '../../encoding/proto/primitives';
import { x25519 } from '@noble/curves/ed25519.js';

/** Generic error message for all unseal failures */
export {};
const GENERIC_ERROR = 'Sealed sender verification failed';

/**
 * Parse decrypted envelope to extract certificate and message.
 */
function parseEnvelope(envelope: Uint8Array): {
  certificate: SenderCertificate;
  message: Uint8Array;
  contentHint?: ContentHint;
  groupId?: Uint8Array;
} {
  let offset = 0;

  // Read certificate length
  const { value: certLen, bytesRead: certLenBytes } = decodeVarint(envelope, offset);
  offset += certLenBytes;

  if (offset + certLen > envelope.length) {
    throw new Error(GENERIC_ERROR);
  }

  // Read certificate bytes
  const certBytes = envelope.slice(offset, offset + certLen);
  offset += certLen;

  // Read message length
  const { value: msgLen, bytesRead: msgLenBytes } = decodeVarint(envelope, offset);
  offset += msgLenBytes;

  if (offset + msgLen > envelope.length) {
    throw new Error(GENERIC_ERROR);
  }

  // Read message bytes
  const message = envelope.slice(offset, offset + msgLen);
  offset += msgLen;

  // Read content hint (optional)
  let contentHint: ContentHint | undefined;
  if (offset < envelope.length) {
    contentHint = envelope[offset] as ContentHint;
    offset += 1;
  }

  // Read group ID (optional)
  let groupId: Uint8Array | undefined;
  if (offset < envelope.length) {
    const { value: groupIdLen, bytesRead: groupIdLenBytes } = decodeVarint(envelope, offset);
    offset += groupIdLenBytes;

    if (groupIdLen > 0 && offset + groupIdLen <= envelope.length) {
      groupId = envelope.slice(offset, offset + groupIdLen);
    }
  }

  // Deserialize certificate
  const certificate = deserializeSenderCertificate(certBytes);

  return { certificate, message, contentHint, groupId };
}

/**
 * Unseal a V2 multi-recipient Sealed Sender message.
 *
 * @param options V2 unsealing options
 * @returns Decrypted content with validated sender certificate
 * @throws Error (generic) if any validation fails
 *
 * @example
 * ```typescript
 * const content = await unsealV2({
 *   sealedMessage: receivedMessage,
 *   recipientIdentityPrivate: myPrivateKey,
 *   recipientIdentityPublic: myPublicKey,
 *   recipientServiceId: 'my-user-id',
 *   recipientDeviceId: 1,
 *   trustRoots: [trustRootPublicKey],
 * });
 * ```
 */
export async function unsealV2(
  options: UnsealV2Options
): Promise<UnidentifiedSenderMessageContent> {
  const {
    sealedMessage,
    recipientIdentityPrivate,
    recipientIdentityPublic,
    recipientServiceId,
    recipientDeviceId,
    trustRoots,
    currentTime,
  } = options;

  // Track sensitive material for secure zeroing
  const toZero: Uint8Array[] = [];

  // ========================================================================
  // Step 1: Validate version and find my recipient entry
  // ========================================================================
  const version = sealedMessage.version;
  if (
    version !== SEALED_SENDER_V2_UUID_VERSION &&
    version !== SEALED_SENDER_V2_SERVICE_ID_VERSION
  ) {
    throw new Error(GENERIC_ERROR);
  }

  // Find my recipient entry
  const myRecipient = sealedMessage.recipients.find(
    (r) => r.serviceId === recipientServiceId && r.deviceId === recipientDeviceId
  );

  if (!myRecipient) {
    throw new Error(GENERIC_ERROR);
  }

  try {
    const ephemeralPublic = base64ToBytes(sealedMessage.ephemeralPublic);
    const encryptedMessageKey = base64ToBytes(myRecipient.encryptedMessageKey);
    const receivedAuthTag = base64ToBytes(myRecipient.authenticationTag);
    const messageCiphertext = base64ToBytes(sealedMessage.messageCiphertext);

    if (ephemeralPublic.length !== 32) {
      throw new Error(GENERIC_ERROR);
    }

    // ========================================================================
    // Step 2: Decrypt M using XOR (ephemeral-to-identity ECDH)
    // ========================================================================
    const M = await applyAgreementXor(
      recipientIdentityPrivate,
      ephemeralPublic,
      ephemeralPublic, // For receiving: both ECDH target and IKM are the ephemeral key
      'receiving',
      encryptedMessageKey
    );
    toZero.push(M);

    // ========================================================================
    // Step 3: Verify ephemeral public key consistency
    // This authenticates the XOR decryption - if M was wrong, derived key won't match
    // ========================================================================
    const derivedEphemeralPrivate = await deriveEphemeralPrivateFromM(M);
    toZero.push(derivedEphemeralPrivate);

    const derivedEphemeralPublic = x25519.getPublicKey(derivedEphemeralPrivate);

    if (!constantTimeEqual(ephemeralPublic, derivedEphemeralPublic)) {
      throw new Error(GENERIC_ERROR);
    }

    // ========================================================================
    // Step 4: Derive cipher key K from M
    // ========================================================================
    const cipherKey = await deriveCipherKeyFromM(M);
    toZero.push(cipherKey);

    // ========================================================================
    // Step 5: Decrypt message with AES-GCM-SIV (provides authenticated decryption)
    // ========================================================================
    let envelope: Uint8Array;
    try {
      envelope = aesGcmSivDecryptZeroNonce(cipherKey, messageCiphertext);
    } catch {
      throw new Error(GENERIC_ERROR);
    }

    // ========================================================================
    // Step 6: Parse envelope to get sender certificate
    // ========================================================================
    const { certificate, message, contentHint, groupId } = parseEnvelope(envelope);

    // ========================================================================
    // Step 7: Verify authentication tag (identity-to-identity ECDH)
    // Now that we have sender's identity from certificate, verify auth tag
    // This binds the sender's identity to the message
    // ========================================================================
    const senderIdentityPublic = base64ToBytes(certificate.senderIdentityKey);

    const expectedAuthTag = await computeAuthenticationTag(
      recipientIdentityPrivate,
      recipientIdentityPublic,
      senderIdentityPublic,
      ephemeralPublic,
      encryptedMessageKey,
      'receiving'
    );

    if (!verifyAuthenticationTag(expectedAuthTag, receivedAuthTag)) {
      throw new Error(GENERIC_ERROR);
    }

    // ========================================================================
    // Step 8: Validate sender certificate
    // ========================================================================
    await validateSenderCertificate(certificate, trustRoots, currentTime);

    // Self-send detection
    if (
      certificate.senderUuid === recipientServiceId &&
      certificate.senderDeviceId === recipientDeviceId
    ) {
      throw new Error(GENERIC_ERROR);
    }

    return {
      senderCertificate: certificate,
      signalProtocolMessage: bytesToBase64(message) as Base64,
      contentHint,
      groupId: groupId ? (bytesToBase64(groupId) as Base64) : undefined,
    };
  } finally {
    // Security: Zero all sensitive key material
    for (const arr of toZero) {
      secureZeroBytes(arr);
    }
  }
}
