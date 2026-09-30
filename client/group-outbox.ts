import type { SignalProtocolLocalStore } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import * as CryptoUtils from '../internal/crypto';
import type {
  GroupMemberDevice,
  SignalProtocolRelayServer,
  SealedSenderAuth,
} from '../remote/relay/types';
import {
  appendOutgoingGroupDeviceMessages,
  completeOutgoingMessageIntent,
  confirmOutgoingPreMessages,
  getOutgoingMessageIntent,
  storeOutgoingMessageIntent,
  withOutgoingMessageIntentLock,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import type { SendOptions, SendResult } from './types';

/** The relay phases of a group send, in their order. */
export type GroupSendPhase = 'pre-message' | 'device' | 'sync';

/**
 * The work of one group send.
 *
 * The phases of a send run in order, with a barrier between phases: the
 * pre-messages, then the sender-key confirmation, then the group message and
 * its device posts, then the sync copies. Inside a phase, the items run at the
 * same time. Each relay request takes a slot of the client's relay request
 * bound, and a phase holds no slot.
 */
export interface GroupOutboxContext {
  storage: SignalProtocolLocalStore;
  relay?: SignalProtocolRelayServer;
  senderUserId: string;
  senderDeviceId: number;
  deliveryMode: 'preferred' | 'required' | 'disabled';
  /**
   * Prepare the sender-key payload. When a sender-key distribution is
   * pending, the preparation gets the member devices from readMembers, so the
   * send reads each member's device list once.
   */
  preparePayload(
    groupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number },
    readMembers: () => Promise<GroupMemberDevice[]>
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
  /**
   * Run local work for each item at the same time. It rejects after every
   * item settles, with the error of the first failed item in input order. A
   * stop does not end it.
   */
  prepareEach<T, R>(items: readonly T[], task: (item: T) => Promise<R>): Promise<R[]>;
  /**
   * Run one relay phase: a task for each device message at the same time.
   * Every device is attempted. It rejects after every device settles, with
   * the error of the first failed device in input order.
   */
  sendPhase<R>(
    messages: readonly StoredOutgoingDeviceMessage[],
    task: (message: StoredOutgoingDeviceMessage) => Promise<R>,
    phase: GroupSendPhase
  ): Promise<R[]>;
  /** Send one relay request of a device post under a slot of the bound. */
  postToRelay<T>(send: () => Promise<T>, sealed: boolean): Promise<T>;
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
    return context.postToRelay(
      () =>
        relay.send({
          targetUserId: message.recipientUserId,
          targetDeviceId: message.recipientDeviceId,
          senderUserId: context.senderUserId,
          senderDeviceId: context.senderDeviceId,
          ciphertext: message.ciphertext,
          messageType: message.messageType,
          deliveryClass: 'user-visible',
          timestamp: message.timestamp,
          clientMessageId: intent.clientMessageId,
        }),
      false
    );
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

  // Every pre-message is accepted before the confirmation and the group
  // message. When some fail, the intent keeps only those, so a replay posts
  // only the pre-messages that the relay did not accept.
  const preMessages = intent.preMessages ?? [];
  const accepted: string[] = [];
  try {
    await context.sendPhase(
      preMessages,
      async (message) => {
        await context.postToRelay(
          () =>
            relay.send({
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
            }),
          false
        );
        if (message.clientMessageId !== undefined) accepted.push(message.clientMessageId);
      },
      'pre-message'
    );
  } catch (error) {
    if (accepted.length > 0) {
      await confirmOutgoingPreMessages(context.storage, intent.clientMessageId, accepted);
    }
    throw error;
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
      const shared = intent.groupSharedMessage;
      try {
        const result = await context.postToRelay(
          () =>
            relay.sendMultiRecipientUnidentified!(
              shared.sentMessageBase64,
              auth,
              intent.clientTimestamp,
              'user-visible',
              shared.recipientUserIds,
              intent.clientMessageId
            ),
          true
        );
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
        skippedUsers = result.uuids404;
        sharedSucceeded = true;
      } catch (error) {
        if (!(error instanceof SealedSenderAuthError)) throw error;
        if (intent.groupSharedMessage.deliveryMode === 'required') throw error;
        await context.prepareEach(intent.groupSharedMessage.recipientUserIds, (recipientUserId) =>
          context.reportIdentifiedFallback(recipientUserId)
        );
      }
    }
  }

  const sharedUsers = new Set(intent.groupSharedMessage?.recipientUserIds ?? []);
  const usersToRepair = new Set(skippedUsers);
  const forceIdentified = Boolean(intent.groupSharedMessage && !sharedSucceeded);
  const devicePosts = intent.deviceMessages.filter(
    (message) =>
      !sharedSucceeded ||
      !sharedUsers.has(message.recipientUserId) ||
      usersToRepair.has(message.recipientUserId)
  );
  const results = await context.sendPhase(
    devicePosts,
    (message) => sendStoredDeviceMessage(context, intent, message, forceIdentified),
    'device'
  );
  if (messageId.startsWith('group-') && results[0]) {
    messageId = results[0].messageId;
    timestamp = results[0].serverTimestamp;
  }

  if (skippedUsers.length > 0) {
    const refreshed = await context.resolveMemberDevices(intent.recipientId, {
      clientMessageId: intent.clientMessageId,
      groupMemberUserIds: skippedUsers,
    });
    const knownTargets = new Set(
      intent.deviceMessages.map(
        (message) => `${message.recipientUserId}\u0000${String(message.recipientDeviceId)}`
      )
    );
    const groupCiphertext = intent.groupCiphertext;
    const additions = await context.prepareEach(
      refreshed.filter(
        (member) => !knownTargets.has(`${member.userId}\u0000${String(member.deviceId)}`)
      ),
      (member) =>
        context.prepareDeviceMessage(
          member,
          intent.recipientId,
          groupCiphertext,
          intent.clientTimestamp
        )
    );
    if (additions.length > 0) {
      intent = await appendOutgoingGroupDeviceMessages(
        context.storage,
        intent.clientMessageId,
        additions
      );
      const extended = intent;
      await context.sendPhase(
        additions,
        (message) => sendStoredDeviceMessage(context, extended, message),
        'device'
      );
    }
  }

  // The sync copies start after every device post settles.
  await context.sendPhase(
    intent.syncMessages,
    (message) =>
      context.postToRelay(
        () =>
          relay.send({
            targetUserId: message.recipientUserId,
            targetDeviceId: message.recipientDeviceId,
            senderUserId: context.senderUserId,
            senderDeviceId: context.senderDeviceId,
            ciphertext: message.ciphertext,
            messageType: message.messageType,
            deliveryClass: 'background-sync',
            timestamp: message.timestamp,
            clientMessageId: message.clientMessageId,
          }),
        false
      ),
    'sync'
  );

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
    // One device-list read for each member in this send.
    let memberRead: Promise<GroupMemberDevice[]> | undefined;
    const readMembers = () => (memberRead ??= context.resolveMemberDevices(groupId, options));
    const preparedPayload = await context.preparePayload(
      groupId,
      plaintextBytes,
      { ...options, timestamp: clientTimestamp },
      readMembers
    );
    const encryptedMessageBase64 = preparedPayload.ciphertext;
    const members = context.relay ? await readMembers() : [];
    const otherMembers = members.filter((member) => member.userId !== context.senderUserId);
    const groupSharedMessage = await context.prepareSharedMessage(
      groupId,
      otherMembers,
      encryptedMessageBase64
    );
    const deviceMessages = await context.prepareEach(otherMembers, (member) =>
      context.prepareDeviceMessage(member, groupId, encryptedMessageBase64, clientTimestamp)
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
