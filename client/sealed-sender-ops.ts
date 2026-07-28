/**
 * Sealed Sender Operations
 *
 * Provides seal/unseal wrapping for the message send/receive pipeline.
 * Called by SignalProtocolServiceCipher when sealed sender is enabled.
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import type { SealedSenderConfig } from './config';
import type { Envelope } from '../remote/relay/types';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';
import type { Base64 } from '../types';
import {
  SealedSenderContentType,
  SEALED_SENDER_V2_SERVICE_ID_VERSION,
  SEALED_SENDER_V2_UUID_VERSION,
} from '../internal/protocol/sealed-sender/types';

/**
 * Wrap an encrypted ciphertext with sealed sender encryption.
 *
 * Takes the already-encrypted Signal Protocol message and wraps it with
 * an additional layer that hides the sender's identity from the server.
 *
 * @param ciphertextBase64 - Base64-encoded Signal Protocol ciphertext
 * @param senderCertificateBase64 - Base64-encoded serialized SenderCertificate
 * @param senderIdentityPrivate - Sender's X25519 identity private key
 * @param recipientIdentityPublic - Recipient's X25519 identity public key
 * @param config - Sealed sender config with trust roots
 * @param contentType - How the recipient should decrypt the inner ciphertext.
 *   The outer envelope is `unidentified_sender` for every sealed message, so
 *   this is the only signal that a payload is a framed SenderKeyMessage.
 * @returns Base64-encoded sealed sender message
 */
export {};
export async function sealMessage(
  ciphertextBase64: string,
  senderCertificateBase64: string,
  senderIdentityPrivate: Uint8Array,
  recipientIdentityPublic: Uint8Array,
  _config: SealedSenderConfig,
  _providedLogger?: ILogger,
  contentType?: SealedSenderContentType
): Promise<string> {
  const { seal, deserializeSenderCertificate, encodeUnidentifiedSenderMessage } =
    await import('../internal/protocol/sealed-sender');
  const { base64ToBytes, bytesToBase64 } = await import('../internal/crypto');

  // Deserialize the sender certificate
  const certBytes = base64ToBytes(senderCertificateBase64 as Base64);
  const senderCertificate = deserializeSenderCertificate(certBytes);

  // Convert ciphertext to bytes for seal()
  const signalProtocolMessage = base64ToBytes(ciphertextBase64 as Base64);

  // Seal the message
  const sealed = await seal({
    senderCertificate,
    senderIdentityPrivate,
    recipientIdentityPublic,
    signalProtocolMessage,
    contentType,
  });

  // Serialize: version byte + protobuf-encoded message (Sealed Sender wire format)
  const protoBytes = encodeUnidentifiedSenderMessage({
    ephemeralPublic: base64ToBytes(sealed.ephemeralPublic as Base64),
    encryptedStatic: base64ToBytes(sealed.encryptedStatic as Base64),
    encryptedMessage: base64ToBytes(sealed.encryptedMessage as Base64),
  });

  // Prepend version byte
  const sealedBytes = new Uint8Array(1 + protoBytes.length);
  sealedBytes[0] = sealed.version;
  sealedBytes.set(protoBytes, 1);

  return bytesToBase64(sealedBytes);
}

/**
 * Unseal a sealed sender message to reveal the sender and inner ciphertext.
 *
 * Called when an incoming envelope has messageType === 'unidentified_sender'.
 * Validates the certificate chain, reveals sender identity, and returns
 * the inner Signal Protocol ciphertext for normal decryption.
 *
 * @param sealedCiphertextBase64 - Base64-encoded sealed sender message
 * @param recipientIdentityPrivate - Recipient's X25519 identity private key
 * @param recipientUuid - Recipient's user ID (for self-send detection)
 * @param recipientDeviceId - Recipient's device ID
 * @param config - Sealed sender config with trust roots
 * @returns Unsealed envelope info with sender identity and inner ciphertext
 */
export async function unsealMessage(
  sealedCiphertextBase64: string,
  recipientIdentityPrivate: Uint8Array,
  recipientUuid: string,
  recipientDeviceId: number,
  config: SealedSenderConfig,
  providedLogger?: ILogger
): Promise<{
  senderUserId: string;
  senderDeviceId: number;
  innerCiphertextBase64: string;
  contentType: SealedSenderContentType;
}> {
  const logger = resolveSignalProtocolLogger(providedLogger);
  const { base64ToBytes, bytesToBase64 } = await import('../internal/crypto');

  // Decode sealed bytes and check version byte for V1 vs V2 dispatch
  const sealedBytes = base64ToBytes(sealedCiphertextBase64 as Base64);
  const versionByte = sealedBytes[0];

  // V2 detection: 0x22 = UUID version (ReceivedMessage), 0x23 = ServiceId version
  if (
    versionByte === SEALED_SENDER_V2_UUID_VERSION ||
    versionByte === SEALED_SENDER_V2_SERVICE_ID_VERSION
  ) {
    return unsealV2Message(
      sealedBytes,
      recipientIdentityPrivate,
      recipientUuid,
      recipientDeviceId,
      config,
      logger
    );
  }

  // V1 path (0x11) — existing code
  const { unseal, decodeUnidentifiedSenderMessage } =
    await import('../internal/protocol/sealed-sender');

  const version = versionByte;
  const sealedProto = decodeUnidentifiedSenderMessage(sealedBytes.subarray(1));

  // Build the UnidentifiedSenderMessage structure
  const sealedMessage = {
    version,
    ephemeralPublic: bytesToBase64(sealedProto.ephemeralPublic) as Base64,
    encryptedStatic: bytesToBase64(sealedProto.encryptedStatic) as Base64,
    encryptedMessage: bytesToBase64(sealedProto.encryptedMessage) as Base64,
  };

  // Build trust roots as base64 strings
  const trustRoots: Base64[] = config.trustRoots.map((root) => bytesToBase64(root) as Base64);

  // Unseal the message
  const content = await unseal({
    sealedMessage,
    recipientIdentityPrivate,
    trustRoots,
    recipientUuid,
    recipientDeviceId,
  });

  logger.debug('Sealed sender message unsealed', {
    category: 'E2EE',
    data: {
      senderUuid: content.senderCertificate.senderUuid,
      senderDeviceId: content.senderCertificate.senderDeviceId,
    },
  });

  return {
    senderUserId: content.senderCertificate.senderUuid,
    senderDeviceId: content.senderCertificate.senderDeviceId,
    innerCiphertextBase64: content.signalProtocolMessage as string,
    contentType: content.contentType,
  };
}

/**
 * Unseal a V2 multi-recipient sealed sender message (per-device view).
 *
 * The server constructs a per-device view: [0x22][C_i(32)][AT_i(16)][e_pub(32)][ciphertext]
 * We deserialize this, build a SealedSenderV2Message, and call unsealV2().
 */
async function unsealV2Message(
  sealedBytes: Uint8Array,
  recipientIdentityPrivate: Uint8Array,
  recipientUuid: string,
  recipientDeviceId: number,
  config: SealedSenderConfig,
  logger: Required<ILogger>
): Promise<{
  senderUserId: string;
  senderDeviceId: number;
  innerCiphertextBase64: string;
  contentType: SealedSenderContentType;
}> {
  const { deserializeReceivedMessage } =
    await import('../internal/protocol/sealed-sender/v2-binary');
  const { unsealV2 } = await import('../internal/protocol/sealed-sender/decryption-v2');
  const { bytesToBase64 } = await import('../internal/crypto');
  const { x25519 } = await import('@noble/curves/ed25519.js');

  // 1. Deserialize per-device ReceivedMessage
  const deserialized = deserializeReceivedMessage(sealedBytes);

  // 2. Derive recipient public key from private
  const recipientIdentityPublic = x25519.getPublicKey(recipientIdentityPrivate);

  // 3. Build SealedSenderV2Message with single recipient entry
  const message = {
    version: SEALED_SENDER_V2_UUID_VERSION as typeof SEALED_SENDER_V2_UUID_VERSION,
    ephemeralPublic: bytesToBase64(deserialized.ephemeralPublic) as Base64,
    recipients: [
      {
        serviceId: recipientUuid,
        deviceId: recipientDeviceId,
        registrationId: 0, // Not needed for unseal — only used in send path
        encryptedMessageKey: bytesToBase64(deserialized.encryptedMessageKey) as Base64,
        authenticationTag: bytesToBase64(deserialized.authenticationTag) as Base64,
      },
    ],
    messageCiphertext: bytesToBase64(deserialized.messageCiphertext) as Base64,
  };

  // 4. Build trust roots as Base64 strings
  const trustRoots: Base64[] = config.trustRoots.map((root) => bytesToBase64(root) as Base64);

  // 5. Call unsealV2
  const content = await unsealV2({
    sealedMessage: message,
    recipientIdentityPrivate,
    recipientIdentityPublic,
    recipientServiceId: recipientUuid,
    recipientDeviceId,
    trustRoots,
  });

  logger.debug('V2 sealed sender message unsealed', {
    category: 'E2EE',
    data: {
      senderUuid: content.senderCertificate.senderUuid,
      senderDeviceId: content.senderCertificate.senderDeviceId,
    },
  });

  return {
    senderUserId: content.senderCertificate.senderUuid,
    senderDeviceId: content.senderCertificate.senderDeviceId,
    innerCiphertextBase64: content.signalProtocolMessage as string,
    contentType: content.contentType,
  };
}

/**
 * Reconstruct an Envelope from an unsealed message.
 *
 * Takes the original sealed sender envelope (with empty sender fields)
 * and fills in the sender identity revealed by unsealing.
 *
 * @param originalEnvelope - The incoming envelope with messageType 'unidentified_sender'
 * @param unsealed - The unsealed sender info and inner ciphertext
 * @returns A new envelope with real sender info and the inner ciphertext
 */
export function reconstructEnvelope(
  originalEnvelope: Envelope,
  unsealed: {
    senderUserId: string;
    senderDeviceId: number;
    innerCiphertextBase64: string;
    contentType: SealedSenderContentType;
  }
): Envelope {
  return {
    ...originalEnvelope,
    senderUserId: unsealed.senderUserId,
    senderDeviceId: unsealed.senderDeviceId,
    ciphertext: unsealed.innerCiphertextBase64,
    messageType: envelopeTypeForContent(unsealed.contentType),
  };
}

/**
 * Map a sealed envelope's content type onto the envelope type the decrypt
 * path routes on.
 *
 * Exported because both receive paths need it — `SignalProtocolServiceCipher`
 * via `reconstructEnvelope`, and `SignalProtocolClient.processIncomingEnvelope`
 * directly. Two copies of this mapping would drift.
 *
 * `SENDERKEY_MESSAGE` is the only case that matters here: it is what keeps
 * group routing working now that no group identifier travels on an envelope,
 * sealed or otherwise. `PREKEY_MESSAGE` and `MESSAGE` both decrypt as pairwise
 * ratchet messages, and the ratchet distinguishes them from the payload
 * itself.
 *
 * The default is unreachable: `isSealedSenderContentType` rejects every other
 * value at the parse, so nothing arrives here that this function cannot map.
 * It exists so that adding an enum member without a route fails loudly rather
 * than silently decrypting as something it is not.
 */
export function envelopeTypeForContent(
  contentType: SealedSenderContentType
): Envelope['messageType'] {
  switch (contentType) {
    case SealedSenderContentType.SENDERKEY_MESSAGE:
      return 'sender_key';
    case SealedSenderContentType.PREKEY_MESSAGE:
    case SealedSenderContentType.MESSAGE:
      return 'ciphertext';
    default:
      throw new Error('Unsupported sealed sender content type');
  }
}
