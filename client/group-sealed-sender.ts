import type { GroupMemberDevice } from '../remote/relay/types';
import type { ISignalProtocolLocalStore, Base64 } from '../types';
import { ProtocolAddress } from '../types/address';
import { base64ToBytes, bytesToBase64 } from '../internal/crypto';
import {
  deserializeSenderCertificate,
  sealMultiRecipient,
} from '../internal/protocol/sealed-sender';
import { serializeSentMessage } from '../internal/protocol/sealed-sender/multi-recipient-message';
import { SealedSenderContentType } from '../internal/protocol/sealed-sender/types';

export interface GroupSealedSenderKeys {
  senderCertificateBase64: string;
  senderIdentityPrivate: Uint8Array;
  senderIdentityPublic: Uint8Array;
}

export interface PreparedGroupSharedMessage {
  sentMessageBase64: string;
  recipientUserIds: string[];
  sharedMembers: GroupMemberDevice[];
  fallbackMembers: GroupMemberDevice[];
}

/**
 * Prepare one immutable multi-recipient sealed-sender body for a group send.
 *
 * Recipient identity and registration data are captured in the body. Callers
 * can persist the returned bytes before transport and replay them verbatim.
 * Members without a known identity remain outside the shared body and must be
 * handled by a separately persisted per-device plan.
 */
export async function prepareGroupSharedMessage(input: {
  storage: ISignalProtocolLocalStore;
  senderKeys: GroupSealedSenderKeys;
  members: GroupMemberDevice[];
  encryptedMessageBase64: string;
}): Promise<PreparedGroupSharedMessage | null> {
  const identityByUser = new Map<string, Uint8Array>();
  const uniqueUserIds = [...new Set(input.members.map((member) => member.userId))];

  for (const userId of uniqueUserIds) {
    const identityRecord = await input.storage.getContactIdentity(
      ProtocolAddress.create(userId, 1)
    );
    if (identityRecord) {
      identityByUser.set(userId, base64ToBytes(identityRecord.identity.x25519PublicKey));
    }
  }

  const sharedMembers = input.members.filter((member) => identityByUser.has(member.userId));
  const fallbackMembers = input.members.filter((member) => !identityByUser.has(member.userId));
  if (sharedMembers.length === 0) return null;

  const recipients = await Promise.all(
    sharedMembers.map(async (member) => {
      const session = await input.storage.getSessionRecord(
        ProtocolAddress.create(member.userId, member.deviceId)
      );
      return {
        serviceId: member.userId,
        deviceId: member.deviceId,
        registrationId: session?.currentSession?.remoteRegistrationId ?? 0,
        identityPublic: identityByUser.get(member.userId)!,
      };
    })
  );

  const sealed = await sealMultiRecipient({
    senderCertificate: deserializeSenderCertificate(
      base64ToBytes(input.senderKeys.senderCertificateBase64 as Base64)
    ),
    senderIdentityPrivate: input.senderKeys.senderIdentityPrivate,
    senderIdentityPublic: input.senderKeys.senderIdentityPublic,
    recipients,
    signalProtocolMessage: base64ToBytes(input.encryptedMessageBase64 as Base64),
    contentType: SealedSenderContentType.SENDERKEY_MESSAGE,
  });

  const recipientsByUser = new Map<
    string,
    {
      serviceId: string;
      devices: Array<{ deviceId: number; registrationId: number }>;
      encryptedMessageKey: Uint8Array;
      authenticationTag: Uint8Array;
    }
  >();

  for (const recipient of sealed.recipients) {
    const existing = recipientsByUser.get(recipient.serviceId);
    if (existing) {
      existing.devices.push({
        deviceId: recipient.deviceId,
        registrationId: recipient.registrationId,
      });
    } else {
      recipientsByUser.set(recipient.serviceId, {
        serviceId: recipient.serviceId,
        devices: [
          {
            deviceId: recipient.deviceId,
            registrationId: recipient.registrationId,
          },
        ],
        encryptedMessageKey: base64ToBytes(recipient.encryptedMessageKey as Base64),
        authenticationTag: base64ToBytes(recipient.authenticationTag as Base64),
      });
    }
  }

  return {
    sentMessageBase64: bytesToBase64(
      serializeSentMessage(
        [...recipientsByUser.values()],
        [],
        base64ToBytes(sealed.ephemeralPublic as Base64),
        base64ToBytes(sealed.messageCiphertext as Base64)
      )
    ),
    recipientUserIds: [...recipientsByUser.keys()],
    sharedMembers,
    fallbackMembers,
  };
}
