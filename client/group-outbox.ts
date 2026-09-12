import type { ISignalProtocolLocalStore } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import * as CryptoUtils from '../internal/crypto';
import type {
  GroupMemberDevice,
  ISignalProtocolRelayServer,
  SealedSenderAuth,
} from '../remote/relay/types';
import {
  appendOutgoingGroupDeviceMessages,
  completeOutgoingMessageIntent,
  getOutgoingMessageIntent,
  storeOutgoingMessageIntent,
  withOutgoingMessageIntentLock,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import type { SendOptions, SendResult } from './types';

export interface GroupOutboxContext {
  storage: ISignalProtocolLocalStore;
  relay?: ISignalProtocolRelayServer;
  senderUserId: string;
  senderDeviceId: number;
  deliveryMode: 'preferred' | 'required' | 'disabled';
  preparePayload(
    groupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number }
  ): Promise<{
    ciphertext: string;
    preMessages: StoredOutgoingDeviceMessage[];
    senderKeyDistributionId?: string;
  }>;
  confirmSenderKeyDistributionSent(groupId: string, senderKeyId: string): Promise<void>;
  resolveMemberDevices(
    groupId: string,
    options: SendOptions & { clientMessageId: string }
  ): Promise<GroupMemberDevice[]>;
  prepareSharedMessage(
    groupId: string,
    members: GroupMemberDevice[],
    ciphertext: string
  ): Promise<StoredOutgoingMessageIntent['groupSharedMessage']>;
  prepareDeviceMessage(
    member: GroupMemberDevice,
    groupId: string,
    ciphertext: string,
    timestamp: number
  ): Promise<StoredOutgoingDeviceMessage>;
  prepareSyncMessages(
    groupId: string,
    plaintextBytes: Uint8Array,
    timestamp: number,
    clientMessageId: string
  ): Promise<StoredOutgoingDeviceMessage[]>;
  resolveGroupAuthorization(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<Extract<SealedSenderAuth, { type: 'groupSendToken' }> | null>;
  reportIdentifiedFallback(recipientUserId: string): Promise<void>;
  sendPreparedSealedDevice(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    auth: SealedSenderAuth
  ): Promise<{ messageId: string; serverTimestamp: number }>;
}

async function sendStoredDeviceMessage(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  message: StoredOutgoingDeviceMessage,
  forceIdentified = false
): Promise<{ messageId: string; serverTimestamp: number }> {
  const relay = context.relay;
  if (!relay) throw new Error('Relay is required for a stored group transmission');
  if (message.sealedSenderMessage && !relay.sendMultiRecipientUnidentified) {
    if (message.sealedSenderDeliveryMode === 'required') {
      throw new EncryptionError(
        'Required group sealed-sender transport is unavailable',
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { recipientUserId: message.recipientUserId }
      );
    }
    return sendStoredDeviceMessage(context, intent, message, true);
  }
  if (forceIdentified || !message.sealedSenderMessage) {
    return relay.send({
      targetUserId: message.recipientUserId,
      targetDeviceId: message.recipientDeviceId,
      senderUserId: context.senderUserId,
      senderDeviceId: context.senderDeviceId,
      ciphertext: message.ciphertext,
      messageType: message.messageType,
      deliveryClass: 'user-visible',
      timestamp: message.timestamp,
      clientMessageId: intent.clientMessageId,
    });
  }

  const auth: SealedSenderAuth | null =
    message.sealedSenderAuthorization === 'access_key' && message.sealedSenderAccessKey
      ? {
          type: 'accessKey',
          unidentifiedAccessKey: message.sealedSenderAccessKey,
        }
      : message.sealedSenderAuthorization === 'group_send_token'
        ? await context.resolveGroupAuthorization(intent.recipientId, [message.recipientUserId])
        : null;
  if (!auth) {
    if (message.sealedSenderDeliveryMode === 'required') {
      throw new Error('Required group sealed-sender authorization is unavailable');
    }
    return sendStoredDeviceMessage(context, intent, message, true);
  }
  return context.sendPreparedSealedDevice(intent, message, auth);
}

async function sendStoredGroupIntent(
  context: GroupOutboxContext,
  initialIntent: StoredOutgoingMessageIntent
): Promise<SendResult> {
  let intent = initialIntent;
  if (intent.kind !== 'group') throw new Error('Expected a group outbox intent');
  if (!intent.groupCiphertext) throw new Error('Corrupt group outbox intent');
  const relay = context.relay;
  if (!relay) {
    const localResult = {
      clientMessageId: intent.clientMessageId,
      messageId: `local-${intent.clientTimestamp}`,
      timestamp: intent.clientTimestamp,
      recipientDeviceCount: intent.groupRecipientDeviceCount ?? 0,
      groupId: intent.recipientId,
    };
    await completeOutgoingMessageIntent(context.storage, intent.clientMessageId, localResult);
    return localResult;
  }

  let messageId = `group-${intent.recipientId}-${String(intent.clientTimestamp)}`;
  let timestamp = intent.clientTimestamp;
  let sharedSucceeded = false;
  let skippedUsers: string[] = [];

  for (const message of intent.preMessages ?? []) {
    await relay.send({
      targetUserId: message.recipientUserId,
      targetDeviceId: message.recipientDeviceId,
      senderUserId: context.senderUserId,
      senderDeviceId: context.senderDeviceId,
      ciphertext: message.ciphertext,
      messageType: message.messageType,
      deliveryClass: 'background-sync',
      timestamp: message.timestamp,
      clientMessageId: message.clientMessageId,
      recipientRegistrationId: message.recipientRegistrationId,
    });
  }
  if (intent.groupSenderKeyDistributionId) {
    await context.confirmSenderKeyDistributionSent(
      intent.recipientId,
      intent.groupSenderKeyDistributionId
    );
  }

  if (
    intent.groupSharedMessage?.deliveryMode === 'required' &&
    !relay.sendMultiRecipientUnidentified
  ) {
    throw new EncryptionError(
      'Required group sealed-sender transport is unavailable',
      EncryptionErrorCode.SEALED_SENDER_REQUIRED,
      { groupId: intent.recipientId }
    );
  }

  if (intent.groupSharedMessage && relay.sendMultiRecipientUnidentified) {
    const auth = await context.resolveGroupAuthorization(
      intent.groupSharedMessage.groupId,
      intent.groupSharedMessage.recipientUserIds
    );
    if (!auth) {
      if (intent.groupSharedMessage.deliveryMode === 'required') {
        throw new Error('Required group sealed-sender authorization is unavailable');
      }
    } else {
      try {
        const result = await relay.sendMultiRecipientUnidentified(
          intent.groupSharedMessage.sentMessageBase64,
          auth,
          intent.clientTimestamp,
          'user-visible',
          intent.groupSharedMessage.recipientUserIds,
          intent.clientMessageId
        );
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
        skippedUsers = result.uuids404;
        sharedSucceeded = true;
      } catch (error) {
        if (!(error instanceof SealedSenderAuthError)) throw error;
        if (intent.groupSharedMessage.deliveryMode === 'required') throw error;
        await Promise.all(
          intent.groupSharedMessage.recipientUserIds.map((recipientUserId) =>
            context.reportIdentifiedFallback(recipientUserId)
          )
        );
      }
    }
  }

  const sharedUsers = new Set(intent.groupSharedMessage?.recipientUserIds ?? []);
  const usersToRepair = new Set(skippedUsers);
  const forceIdentified = Boolean(intent.groupSharedMessage && !sharedSucceeded);
  for (const message of intent.deviceMessages) {
    if (sharedSucceeded && sharedUsers.has(message.recipientUserId)) {
      if (!usersToRepair.has(message.recipientUserId)) continue;
    }
    const result = await sendStoredDeviceMessage(context, intent, message, forceIdentified);
    if (messageId.startsWith('group-')) {
      messageId = result.messageId;
      timestamp = result.serverTimestamp;
    }
  }

  if (skippedUsers.length > 0) {
    const refreshed = (
      await Promise.all(skippedUsers.map((userId) => relay.getActiveDevices(userId)))
    ).flat();
    const knownTargets = new Set(
      intent.deviceMessages.map(
        (message) => `${message.recipientUserId}\u0000${String(message.recipientDeviceId)}`
      )
    );
    const additions: StoredOutgoingDeviceMessage[] = [];
    for (const member of refreshed) {
      const target = `${member.userId}\u0000${String(member.deviceId)}`;
      if (knownTargets.has(target)) continue;
      additions.push(
        await context.prepareDeviceMessage(
          member,
          intent.recipientId,
          intent.groupCiphertext,
          intent.clientTimestamp
        )
      );
    }
    if (additions.length > 0) {
      intent = await appendOutgoingGroupDeviceMessages(
        context.storage,
        intent.clientMessageId,
        additions
      );
      for (const message of additions) {
        await sendStoredDeviceMessage(context, intent, message);
      }
    }
  }

  for (const message of intent.syncMessages) {
    await relay.send({
      targetUserId: message.recipientUserId,
      targetDeviceId: message.recipientDeviceId,
      senderUserId: context.senderUserId,
      senderDeviceId: context.senderDeviceId,
      ciphertext: message.ciphertext,
      messageType: message.messageType,
      deliveryClass: 'background-sync',
      timestamp: message.timestamp,
      clientMessageId: message.clientMessageId,
    });
  }

  const result = {
    clientMessageId: intent.clientMessageId,
    messageId,
    timestamp,
    recipientDeviceCount: intent.groupRecipientDeviceCount ?? intent.deviceMessages.length,
    groupId: intent.recipientId,
  };
  await completeOutgoingMessageIntent(context.storage, intent.clientMessageId, result);
  return result;
}

export async function sendGroupWithExactOutbox(
  context: GroupOutboxContext,
  groupId: string,
  plaintextBytes: Uint8Array,
  options: SendOptions & { clientMessageId: string }
): Promise<SendResult> {
  return withOutgoingMessageIntentLock(context.storage, options.clientMessageId, async () => {
    const plaintextDigest = CryptoUtils.bytesToBase64(await CryptoUtils.sha256(plaintextBytes));
    const groupMemberUserIds = [...new Set(options.groupMemberUserIds ?? [])].sort();
    const existing = await getOutgoingMessageIntent(context.storage, options.clientMessageId);

    if (existing) {
      if (
        existing.kind !== 'group' ||
        existing.recipientId !== groupId ||
        existing.plaintextDigest !== plaintextDigest ||
        (options.timestamp !== undefined && existing.clientTimestamp !== options.timestamp) ||
        JSON.stringify(existing.groupMemberUserIds) !== JSON.stringify(groupMemberUserIds)
      ) {
        throw new Error('A clientMessageId cannot identify two different logical sends');
      }
      if (existing.result) return existing.result;
      return sendStoredGroupIntent(context, existing);
    }

    const clientTimestamp = options.timestamp ?? Date.now();
    const preparedPayload = await context.preparePayload(groupId, plaintextBytes, {
      ...options,
      timestamp: clientTimestamp,
    });
    const encryptedMessageBase64 = preparedPayload.ciphertext;
    const members = context.relay ? await context.resolveMemberDevices(groupId, options) : [];
    const otherMembers = members.filter((member) => member.userId !== context.senderUserId);
    const groupSharedMessage = await context.prepareSharedMessage(
      groupId,
      otherMembers,
      encryptedMessageBase64
    );
    const deviceMessages = await Promise.all(
      otherMembers.map((member) =>
        context.prepareDeviceMessage(member, groupId, encryptedMessageBase64, clientTimestamp)
      )
    );
    const syncMessages = context.relay
      ? await context.prepareSyncMessages(
          groupId,
          plaintextBytes,
          clientTimestamp,
          options.clientMessageId
        )
      : [];

    const intent: StoredOutgoingMessageIntent = {
      kind: 'group',
      clientMessageId: options.clientMessageId,
      recipientId: groupId,
      plaintextDigest,
      clientTimestamp,
      createdAt: Date.now(),
      transportMode: groupSharedMessage
        ? context.deliveryMode === 'required'
          ? 'sealed_sender_required'
          : 'sealed_sender_preferred'
        : 'identified',
      ...(preparedPayload.preMessages.length > 0 && {
        preMessages: preparedPayload.preMessages,
      }),
      deviceMessages,
      syncMessages,
      groupMemberUserIds,
      groupRecipientDeviceCount: otherMembers.length,
      groupCiphertext: encryptedMessageBase64,
      ...(preparedPayload.senderKeyDistributionId && {
        groupSenderKeyDistributionId: preparedPayload.senderKeyDistributionId,
      }),
      ...(groupSharedMessage && { groupSharedMessage }),
    };
    await storeOutgoingMessageIntent(context.storage, intent);
    return sendStoredGroupIntent(context, intent);
  });
}
