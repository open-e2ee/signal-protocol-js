/**
 * Sealed Sender Client Boundary
 *
 * Provides seal/unseal wrapping for the message send/receive pipeline.
 * Called by SignalProtocolServiceCipher when sealed sender is enabled.
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import type { SealedSenderConfig, SealedSenderDeliveryMode } from './config';
import type { Envelope, SealedSenderAuth } from '../remote/relay/types';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';
import type { Base64, ISignalProtocolLocalStore } from '../types';
import { ProtocolAddress } from '../types/address';
import { base64ToBytes } from '../internal/crypto';
import type { EndorsementManager } from './endorsement-manager';
import { UnidentifiedAccessMode, type ContactProfileStateStore } from '../profile/contact-state';
import {
  SealedSenderContentType,
  SEALED_SENDER_V2_SERVICE_ID_VERSION,
  SEALED_SENDER_V2_UUID_VERSION,
} from '../internal/protocol/sealed-sender/types';

export {};

export type SealedSenderProvider = () => Promise<{
  senderCertificateBase64: string;
  senderIdentityPrivate: Uint8Array;
  senderIdentityPublic: Uint8Array;
  config: SealedSenderConfig;
}>;

export interface ResolvedSealedSenderContext {
  senderCertificateBase64: string;
  senderIdentityPrivate: Uint8Array;
  senderIdentityPublic: Uint8Array;
  recipientIdentityPublic: Uint8Array;
  config: SealedSenderConfig;
  auth: SealedSenderAuth;
}

export interface SealedSenderResolutionContext {
  storage: ISignalProtocolLocalStore;
  deliveryMode: SealedSenderDeliveryMode;
  relaySupportsUnidentified: boolean;
  provider?: SealedSenderProvider;
  contactProfileStateStore?: ContactProfileStateStore;
  endorsementManager?: EndorsementManager;
  groupSecretParamsProvider?: (
    groupId: string
  ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>;
  logger: Required<ILogger>;
  useIdentifiedDeliveryOrThrow(recipientUserId: string, reason: string): null;
}

export async function serializeDirectSealedSenderMessage(
  msg: { recipientUserId: string; recipientDeviceId: number },
  ciphertextBase64: string,
  messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key',
  recipientRegistrationId: number | undefined,
  sealedSender: ResolvedSealedSenderContext
): Promise<string> {
  const { sealMultiRecipient, deserializeSenderCertificate } =
    await import('../internal/protocol/sealed-sender');
  const { serializeSentMessage } =
    await import('../internal/protocol/sealed-sender/multi-recipient-message');
  const { base64ToBytes: b64ToBytes, bytesToBase64: bytesToB64 } =
    await import('../internal/crypto');

  const senderCertificate = deserializeSenderCertificate(
    b64ToBytes(sealedSender.senderCertificateBase64 as Base64)
  );
  const sealed = await sealMultiRecipient({
    senderCertificate,
    senderIdentityPrivate: sealedSender.senderIdentityPrivate,
    senderIdentityPublic: sealedSender.senderIdentityPublic,
    recipients: [
      {
        serviceId: msg.recipientUserId,
        deviceId: msg.recipientDeviceId,
        registrationId: recipientRegistrationId ?? 0,
        identityPublic: sealedSender.recipientIdentityPublic,
      },
    ],
    signalProtocolMessage: b64ToBytes(ciphertextBase64 as Base64),
    contentType:
      messageType === 'sender_key'
        ? SealedSenderContentType.SENDERKEY_MESSAGE
        : messageType === 'prekey_bundle'
          ? SealedSenderContentType.PREKEY_MESSAGE
          : SealedSenderContentType.MESSAGE,
  });
  const recipient = sealed.recipients[0];
  if (!recipient) throw new Error('Sealed sender produced no direct recipient');

  return bytesToB64(
    serializeSentMessage(
      [
        {
          serviceId: recipient.serviceId,
          devices: [
            {
              deviceId: recipient.deviceId,
              registrationId: recipient.registrationId,
            },
          ],
          encryptedMessageKey: b64ToBytes(recipient.encryptedMessageKey),
          authenticationTag: b64ToBytes(recipient.authenticationTag),
        },
      ],
      [],
      b64ToBytes(sealed.ephemeralPublic),
      b64ToBytes(sealed.messageCiphertext)
    )
  );
}

export async function resolveSealedSenderContext(
  context: SealedSenderResolutionContext,
  recipientUserId: string,
  groupId?: string
): Promise<ResolvedSealedSenderContext | null> {
  if (context.deliveryMode === 'disabled') return null;
  if (!context.provider || !context.relaySupportsUnidentified) {
    return context.useIdentifiedDeliveryOrThrow(
      recipientUserId,
      'anonymous relay capability is not configured'
    );
  }

  if (groupId && context.endorsementManager) {
    const groupSecretParams = context.groupSecretParamsProvider
      ? await context.groupSecretParamsProvider(groupId)
      : null;
    const endorsementToken = await context.endorsementManager.getTokenForRecipient(
      groupId,
      recipientUserId,
      groupSecretParams ?? undefined
    );
    if (endorsementToken) {
      const { senderCertificateBase64, senderIdentityPrivate, senderIdentityPublic, config } =
        await context.provider();
      const recipientIdentityRecord = await context.storage.getContactIdentity(
        ProtocolAddress.create(recipientUserId, 1)
      );
      if (recipientIdentityRecord) {
        return {
          senderCertificateBase64,
          senderIdentityPrivate,
          senderIdentityPublic,
          recipientIdentityPublic: base64ToBytes(recipientIdentityRecord.identity.x25519PublicKey),
          config,
          auth: {
            type: 'groupSendToken',
            groupSendToken: endorsementToken.token,
            recipientAciBytes: new Map([[recipientUserId, endorsementToken.aciBytes]]),
          },
        };
      }
    }
  }

  const contactStateStore = context.contactProfileStateStore;
  if (!contactStateStore) {
    context.logger.debug('No contact profile state store configured, using identified delivery', {
      category: 'E2EE',
      data: { recipientUserId, groupId },
    });
    return context.useIdentifiedDeliveryOrThrow(
      recipientUserId,
      'recipient capability store is not configured'
    );
  }

  const mode = await contactStateStore.getUnidentifiedAccessMode(recipientUserId);
  if (mode === UnidentifiedAccessMode.DISABLED) {
    context.logger.debug('Sealed sender disabled for recipient, using identified delivery', {
      category: 'E2EE',
      data: { recipientUserId, mode },
    });
    return context.useIdentifiedDeliveryOrThrow(
      recipientUserId,
      'recipient disabled anonymous access'
    );
  }

  const { deriveAccessKey } = await import('../internal/protocol/sealed-sender/delivery-token');
  const { bytesToBase64 } = await import('../internal/crypto');
  let auth: SealedSenderAuth;

  switch (mode) {
    case UnidentifiedAccessMode.UNRESTRICTED:
      auth = {
        type: 'accessKey',
        unidentifiedAccessKey: bytesToBase64(new Uint8Array(16)),
      };
      break;
    case UnidentifiedAccessMode.ENABLED: {
      const recipientProfileKey = await contactStateStore.getContactProfileKey(recipientUserId);
      if (!recipientProfileKey) {
        context.logger.debug('No profile key for ENABLED recipient, using identified delivery', {
          category: 'E2EE',
          data: { recipientUserId },
        });
        return context.useIdentifiedDeliveryOrThrow(
          recipientUserId,
          'recipient access key is unavailable'
        );
      }
      auth = {
        type: 'accessKey',
        unidentifiedAccessKey: bytesToBase64(await deriveAccessKey(recipientProfileKey)),
      };
      break;
    }
    case UnidentifiedAccessMode.UNKNOWN:
    default: {
      const recipientProfileKey = await contactStateStore.getContactProfileKey(recipientUserId);
      auth = {
        type: 'accessKey',
        unidentifiedAccessKey: bytesToBase64(
          recipientProfileKey ? await deriveAccessKey(recipientProfileKey) : new Uint8Array(16)
        ),
      };
      break;
    }
  }

  const { senderCertificateBase64, senderIdentityPrivate, senderIdentityPublic, config } =
    await context.provider();
  const recipientIdentityRecord = await context.storage.getContactIdentity(
    ProtocolAddress.create(recipientUserId, 1)
  );
  if (!recipientIdentityRecord) {
    context.logger.debug('No identity key for recipient, using identified delivery', {
      category: 'E2EE',
      data: { recipientUserId },
    });
    return context.useIdentifiedDeliveryOrThrow(
      recipientUserId,
      'recipient identity key is unavailable'
    );
  }

  return {
    senderCertificateBase64,
    senderIdentityPrivate,
    senderIdentityPublic,
    recipientIdentityPublic: base64ToBytes(recipientIdentityRecord.identity.x25519PublicKey),
    config,
    auth,
  };
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
 * @param relayEnqueueTime - Immutable time when Relay accepted the message
 * @returns Unsealed envelope info with sender identity and inner ciphertext
 */
export async function unsealMessage(
  sealedCiphertextBase64: string,
  recipientIdentityPrivate: Uint8Array,
  recipientUuid: string,
  recipientDeviceId: number,
  config: SealedSenderConfig,
  relayEnqueueTime: number | undefined,
  providedLogger?: ILogger
): Promise<{
  senderUserId: string;
  senderDeviceId: number;
  innerCiphertextBase64: string;
  contentType: SealedSenderContentType;
}> {
  if (
    typeof relayEnqueueTime !== 'number' ||
    !Number.isSafeInteger(relayEnqueueTime) ||
    relayEnqueueTime <= 0
  ) {
    throw new Error('Sealed sender verification requires an immutable Relay enqueue time');
  }

  const logger = resolveSignalProtocolLogger(providedLogger);
  const { base64ToBytes, bytesToBase64 } = await import('../internal/crypto');

  // Decode the only supported sealed-sender transport format.
  const sealedBytes = base64ToBytes(sealedCiphertextBase64 as Base64);
  const versionByte = sealedBytes[0];

  if (
    versionByte === SEALED_SENDER_V2_UUID_VERSION ||
    versionByte === SEALED_SENDER_V2_SERVICE_ID_VERSION
  ) {
    return unsealReceivedMessage(
      sealedBytes,
      recipientIdentityPrivate,
      recipientUuid,
      recipientDeviceId,
      config,
      relayEnqueueTime,
      logger
    );
  }

  throw new Error('Unsupported sealed sender transport version');
}

/**
 * Unseal a multi-recipient sealed sender message (per-device view).
 *
 * The server constructs a per-device view: [0x22][C_i(32)][AT_i(16)][e_pub(32)][ciphertext]
 * We deserialize this, build a sealed message, and call unseal().
 */
async function unsealReceivedMessage(
  sealedBytes: Uint8Array,
  recipientIdentityPrivate: Uint8Array,
  recipientUuid: string,
  recipientDeviceId: number,
  config: SealedSenderConfig,
  relayEnqueueTime: number,
  logger: Required<ILogger>
): Promise<{
  senderUserId: string;
  senderDeviceId: number;
  innerCiphertextBase64: string;
  contentType: SealedSenderContentType;
}> {
  const { deserializeReceivedMessage } =
    await import('../internal/protocol/sealed-sender/multi-recipient-message');
  const { unseal } = await import('../internal/protocol/sealed-sender/decryption');
  const { bytesToBase64 } = await import('../internal/crypto');
  const { x25519 } = await import('@noble/curves/ed25519.js');

  // 1. Deserialize per-device ReceivedMessage
  const deserialized = deserializeReceivedMessage(sealedBytes);

  // 2. Derive recipient public key from private
  const recipientIdentityPublic = x25519.getPublicKey(recipientIdentityPrivate);

  // 3. Build the sealed message with one recipient entry.
  const message = {
    version: SEALED_SENDER_V2_UUID_VERSION as typeof SEALED_SENDER_V2_UUID_VERSION,
    ephemeralPublic: bytesToBase64(deserialized.ephemeralPublic) as Base64,
    recipients: [
      {
        serviceId: recipientUuid,
        deviceId: recipientDeviceId,
        registrationId: 0, // Not needed for unseal. Only used in send path
        encryptedMessageKey: bytesToBase64(deserialized.encryptedMessageKey) as Base64,
        authenticationTag: bytesToBase64(deserialized.authenticationTag) as Base64,
      },
    ],
    messageCiphertext: bytesToBase64(deserialized.messageCiphertext) as Base64,
  };

  // 4. Build trust roots as Base64 strings
  const trustRoots: Base64[] = config.trustRoots.map((root) => bytesToBase64(root) as Base64);
  const certificatePolicy = {
    expectedRelayScopeId: bytesToBase64(config.relayScopeId) as Base64,
    revokedIssuerKeyIds: config.revokedIssuerKeyIds,
  };

  // 5. Unseal and validate the sender credential.
  const content = await unseal({
    sealedMessage: message,
    recipientIdentityPrivate,
    recipientIdentityPublic,
    recipientServiceId: recipientUuid,
    recipientDeviceId,
    trustRoots,
    currentTime: relayEnqueueTime,
    certificatePolicy,
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
 * Exported because both receive paths need it. `SignalProtocolServiceCipher`
 * via `reconstructEnvelope`, and `SignalProtocolClient.processIncomingEnvelope`
 * directly. Two copies of this mapping would drift.
 *
 * `SENDERKEY_MESSAGE` is the only case that matters here. It is what keeps
 * group routing working now that no group identifier travels on an envelope,
 * sealed or otherwise. Both `PREKEY_MESSAGE` and `MESSAGE` decrypt as pairwise
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
