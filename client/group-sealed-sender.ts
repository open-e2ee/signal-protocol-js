import type { GroupMemberDevice } from '../remote/signal-relay/types';
import type { SignalProtocolLocalStore, Base64 } from '../types';
import { ProtocolAddress } from '../types/address';
import { base64ToBytes, bytesToBase64 } from '../internal/crypto';
import {
  deserializeSenderCertificate,
  sealMultiRecipient,
} from '../internal/protocol/sealed-sender';
import {
  deserializeSentMessage,
  serializeSentMessage,
} from '../internal/protocol/sealed-sender/multi-recipient-message';
import { SealedSenderContentType } from '../internal/protocol/sealed-sender/types';
import type { ContentHint } from '../types/messages';

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
  storage: SignalProtocolLocalStore;
  senderKeys: GroupSealedSenderKeys;
  members: GroupMemberDevice[];
  encryptedMessageBase64: string;
  /** The hint that each recipient reads from the seal. */
  contentHint?: ContentHint;
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
  const sealed = await sealGroupBody(
    input.senderKeys,
    recipients,
    input.encryptedMessageBase64,
    input.contentHint
  );
  return {
    sentMessageBase64: sealed.sentMessageBase64,
    recipientUserIds: sealed.recipientUserIds,
    sharedMembers,
    fallbackMembers,
  };
}

/**
 * Seal a stored group body again with new sender keys, from its stored
 * group ciphertext. The new body names the same accounts in the same order,
 * and the same devices with the same registrations, so the shared post
 * declares the same destinations. The group ciphertext and the hint stay the
 * same, so only the outer layer changes. The outer layer of each account
 * goes to its current identity.
 *
 * @throws Error when this client knows no identity of an account of the body.
 */
export async function resealGroupSharedMessage(input: {
  storage: SignalProtocolLocalStore;
  senderKeys: GroupSealedSenderKeys;
  /** The stored body. */
  sentMessageBase64: string;
  /** The accounts of the stored body, in the order of the body. */
  recipientUserIds: readonly string[];
  encryptedMessageBase64: string;
  contentHint?: ContentHint;
}): Promise<string> {
  const { recipients: accounts } = deserializeSentMessage(
    base64ToBytes(input.sentMessageBase64 as Base64)
  );
  if (accounts.length !== input.recipientUserIds.length) {
    throw new Error('A stored group body does not match its accounts');
  }
  const recipients = [];
  for (const [index, { devices }] of accounts.entries()) {
    const userId = input.recipientUserIds[index]!;
    const identityRecord = await input.storage.getContactIdentity(ProtocolAddress.create(userId, 1));
    if (!identityRecord) throw new Error('The identity of a sealed-sender recipient is unknown');
    const identityPublic = base64ToBytes(identityRecord.identity.x25519PublicKey);
    for (const { deviceId, registrationId } of devices) {
      recipients.push({ serviceId: userId, deviceId, registrationId, identityPublic });
    }
  }
  const sealed = await sealGroupBody(
    input.senderKeys,
    recipients,
    input.encryptedMessageBase64,
    input.contentHint
  );
  return sealed.sentMessageBase64;
}

/**
 * Seal one group ciphertext for each recipient device, and serialize the
 * body with the devices of each account together, in the order in which
 * each account first appears.
 */
async function sealGroupBody(
  senderKeys: GroupSealedSenderKeys,
  recipients: Array<{
    serviceId: string;
    deviceId: number;
    registrationId: number;
    identityPublic: Uint8Array;
  }>,
  encryptedMessageBase64: string,
  contentHint: ContentHint | undefined
): Promise<{ sentMessageBase64: string; recipientUserIds: string[] }> {
  const sealed = await sealMultiRecipient({
    senderCertificate: deserializeSenderCertificate(
      base64ToBytes(senderKeys.senderCertificateBase64 as Base64)
    ),
    senderIdentityPrivate: senderKeys.senderIdentityPrivate,
    senderIdentityPublic: senderKeys.senderIdentityPublic,
    recipients,
    signalProtocolMessage: base64ToBytes(encryptedMessageBase64 as Base64),
    contentType: SealedSenderContentType.SENDERKEY_MESSAGE,
    ...(contentHint !== undefined && { contentHint }),
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
  };
}
