/**
 * Sealed Sender V2 Multi-Recipient Encryption
 *
 * Implements V2 multi-recipient sealed sender based on
 * Barbosa & Farshim's randomness reuse technique (IMA 2007).
 *
 * Key efficiency gain: A single ephemeral key and message ciphertext
 * is shared across all recipients, with per-recipient key encapsulation.
 *
 * Algorithm:
 * 1. Generate random M (32 bytes)
 * 2. Derive ephemeral keypair E from M via HKDF(LABEL_R)
 * 3. Derive symmetric key K from M via HKDF(LABEL_K)
 * 4. Encrypt USMC with AES-GCM-SIV(K, nonce=zeros, plaintext=usmc)
 * 5. For each recipient i:
 *    a. ikm = X25519(E_private, recipient_pub[i]) || E_pub || recipient_pub[i]
 *    b. xor_key = HKDF(ikm, info=LABEL_DH)
 *    c. encrypted_key[i] = M XOR xor_key
 *    d. auth_ikm = X25519(sender_identity, recipient_pub[i]) || E_pub || encrypted_key[i] || sender_id_pub || recipient_pub[i]
 *    e. auth_tag[i] = HKDF(auth_ikm, info=LABEL_DH_S) (16 bytes)
 * 6. Return { version, E_pub, recipients[], ciphertext }
 *
 */

import type {
  SealMultiRecipientOptions,
  SealedSenderV2Message,
  SealedSenderV2Recipient,
} from './types';
import { SEALED_SENDER_V2_UUID_VERSION, V2_RANDOM_M_BYTES } from './types';
import type { Base64 } from '../../../types';
import { serializeSenderCertificate } from './certificate';
import {
  deriveEphemeralFromM,
  deriveCipherKeyFromM,
  applyAgreementXor,
  computeAuthenticationTag,
} from './v2-helpers';
import {
  generateRandomBytes,
  bytesToBase64,
  concatBytes,
  secureZeroBytes,
  aesGcmSivEncryptZeroNonce,
} from '../../crypto';
import { encodeVarint } from '../../encoding/proto/primitives';

/** Generic error message for all seal failures */
export {};
const GENERIC_ERROR = 'Sealed sender encryption failed';

/**
 * Serialize envelope (certificate + message) for encryption.
 *
 * Format matches V1 for consistency:
 * varint(certLen) || certBytes || varint(msgLen) || msgBytes || [contentHint] || [groupId]
 */
function serializeEnvelope(
  certBytes: Uint8Array,
  message: Uint8Array,
  contentHint?: number,
  groupId?: Uint8Array
): Uint8Array {
  const parts: Uint8Array[] = [];

  // Certificate length as varint
  parts.push(encodeVarint(certBytes.length));
  parts.push(certBytes);

  // Message length as varint
  parts.push(encodeVarint(message.length));
  parts.push(message);

  // Content hint (1 byte)
  parts.push(new Uint8Array([contentHint ?? 0]));

  // Group ID (optional with length prefix)
  if (groupId && groupId.length > 0) {
    parts.push(encodeVarint(groupId.length));
    parts.push(groupId);
  } else {
    parts.push(new Uint8Array([0]));
  }

  return concatBytes(...parts);
}

/**
 * Seal a Signal Protocol message for multiple recipients using V2 format.
 *
 * Uses randomness reuse (Barbosa & Farshim 2007) for efficiency:
 * - Single ephemeral key shared across all recipients
 * - Single message ciphertext shared across all recipients
 * - Per-recipient key encapsulation via XOR with HKDF-derived key
 * - Per-recipient auth tag using identity-to-identity ECDH
 *
 * @param options Multi-recipient sealing options
 * @returns V2 sealed sender message
 * @throws Error (generic) if any validation fails
 *
 * @example
 * ```typescript
 * const sealed = await sealMultiRecipient({
 *   senderCertificate: cert,
 *   senderIdentityPrivate: myPrivateKey,
 *   senderIdentityPublic: myPublicKey,
 *   recipients: [
 *     { serviceId: 'user1', deviceId: 1, registrationId: 12345, identityPublic: user1Pub },
 *     { serviceId: 'user2', deviceId: 1, registrationId: 23456, identityPublic: user2Pub },
 *   ],
 *   signalProtocolMessage: encryptedMessage,
 * });
 * ```
 */
export async function sealMultiRecipient(
  options: SealMultiRecipientOptions
): Promise<SealedSenderV2Message> {
  const {
    senderCertificate,
    senderIdentityPrivate,
    senderIdentityPublic,
    recipients,
    signalProtocolMessage,
    contentHint,
    groupId,
  } = options;

  // Validate recipients
  if (!recipients || recipients.length === 0) {
    throw new Error(GENERIC_ERROR);
  }

  // Track sensitive material for secure zeroing
  const toZero: Uint8Array[] = [];

  try {
    // ========================================================================
    // Step 1: Generate random M (32 bytes)
    // ========================================================================
    const M = await generateRandomBytes(V2_RANDOM_M_BYTES);
    toZero.push(M);

    // ========================================================================
    // Step 2: Derive ephemeral keypair from M (using LABEL_R)
    // ========================================================================
    const ephemeral = await deriveEphemeralFromM(M);
    toZero.push(ephemeral.privateKey);

    // ========================================================================
    // Step 3: Derive symmetric cipher key K from M (using LABEL_K)
    // ========================================================================
    const cipherKey = await deriveCipherKeyFromM(M);
    toZero.push(cipherKey);

    // ========================================================================
    // Step 4: Serialize and encrypt envelope with AES-GCM-SIV
    // ========================================================================
    const certBytes = serializeSenderCertificate(senderCertificate);
    const envelope = serializeEnvelope(certBytes, signalProtocolMessage, contentHint, groupId);

    // AES-GCM-SIV with zero nonce (safe because key is single-use)
    const messageCiphertext = aesGcmSivEncryptZeroNonce(cipherKey, envelope);

    // ========================================================================
    // Step 5: Per-recipient key encapsulation
    // Group by serviceId and compute C_i/AT_i once per unique identity, not
    // once per destination device.
    // ========================================================================
    const recipientEntries: SealedSenderV2Recipient[] = [];

    // Group recipients by serviceId — all devices of the same user share one identity key
    const groupedByUser = new Map<string, typeof recipients>();
    for (const recipient of recipients) {
      const group = groupedByUser.get(recipient.serviceId);
      if (group) {
        group.push(recipient);
      } else {
        groupedByUser.set(recipient.serviceId, [recipient]);
      }
    }

    for (const [, userDevices] of groupedByUser) {
      const identityPublic = userDevices[0]!.identityPublic;

      // 5a-5c. Compute encrypted message key ONCE per unique identity
      const encryptedMessageKey = await applyAgreementXor(
        ephemeral.privateKey,
        ephemeral.publicKey,
        identityPublic,
        'sending',
        M
      );

      // 5d-5e. Compute authentication tag ONCE per unique identity
      const authenticationTag = await computeAuthenticationTag(
        senderIdentityPrivate,
        senderIdentityPublic,
        identityPublic,
        ephemeral.publicKey,
        encryptedMessageKey,
        'sending'
      );

      const encryptedMessageKeyBase64 = bytesToBase64(encryptedMessageKey) as Base64;
      const authenticationTagBase64 = bytesToBase64(authenticationTag) as Base64;

      // Emit one entry per device, sharing the same C_i/AT_i
      for (const device of userDevices) {
        recipientEntries.push({
          serviceId: device.serviceId,
          deviceId: device.deviceId,
          registrationId: device.registrationId,
          encryptedMessageKey: encryptedMessageKeyBase64,
          authenticationTag: authenticationTagBase64,
        });
      }
    }

    // ========================================================================
    // Step 6: Return V2 message
    // ========================================================================
    return {
      version: SEALED_SENDER_V2_UUID_VERSION,
      ephemeralPublic: bytesToBase64(ephemeral.publicKey) as Base64,
      recipients: recipientEntries,
      messageCiphertext: bytesToBase64(messageCiphertext) as Base64,
    };
  } finally {
    // Security: Zero all sensitive key material
    for (const arr of toZero) {
      secureZeroBytes(arr);
    }
  }
}

// Re-export deterministic helpers within the protocol module.
export {
  deriveEphemeralFromM,
  deriveCipherKeyFromM,
  applyAgreementXor,
  computeAuthenticationTag,
} from './v2-helpers';
