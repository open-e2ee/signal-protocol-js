import type { SenderKeyDistributionMessage } from '../internal/protocol/sender-keys';
import type { DataMessageInput } from './types';
import * as CryptoUtils from '../internal/crypto';
import {
  MediaAttachmentCleanupReason,
  MediaAttachmentMessageType,
  type MediaAttachmentDeleteSyncInput,
} from '../media';

export {};
export type { MediaAttachmentDeleteSyncInput } from '../media';

export interface ParsedReceiptContent {
  type: string;
  timestamps: number[];
}

export interface ParsedTypingContent {
  action: string;
  groupId?: string;
}

export interface SentSyncTranscriptInput {
  conversationId: string;
  serializedContent: Uint8Array;
  timestamp: number;
  recipientUserId?: string;
}

export interface ReadSyncEntryInput {
  senderUserId: string;
  timestamp: number;
}

export interface ViewOnceOpenSyncInput {
  senderUserId: string;
  timestamp: number;
}

export interface ConfigurationSyncInput {
  readReceipts: boolean;
  typingIndicators: boolean;
}

export interface UsernameStateSyncInput {
  username: string | null;
  link: {
    entropy: string;
    handle: string;
  } | null;
}

export interface RecipientUsernameSyncInput {
  userId: string;
  username: string | null;
  uuid?: string | null;
  learnedAt: number;
}

export interface VerificationStateSyncInput {
  targetUserId: string;
  identityKey: string;
  state: 'default' | 'verified';
  changedAt: number;
}

export interface TaskNotificationAckSyncInput {
  taskIds: string[];
  acknowledgedAt: number;
  acknowledgedOnDevice: number;
  reason: 'dismissed' | 'viewed' | 'actioned';
}

export interface BlockedRecipientsSyncInput {
  recipients: Array<{
    recipientId: string;
    blockedAt: number;
  }>;
  syncedAt: number;
}

export interface ParsedSyncContent {
  type:
    | 'sent'
    | 'read'
    | 'viewOnceOpen'
    | 'mediaAttachmentDelete'
    | 'configuration'
    | 'usernameState'
    | 'recipientUsername'
    | 'verificationState'
    | 'taskNotificationAck'
    | 'blocked';
  conversationId?: string;
  timestamp?: number;
  recipientUserId?: string;
  targetUserId?: string;
  userId?: string;
  storageId?: string;
  attachmentId?: string;
  reason?: string;
}

export interface InspectedSignalProtocolContent {
  timestamp?: number;
  conversationId?: string;
  receipt: ParsedReceiptContent | null;
  typing: ParsedTypingContent | null;
  sync: ParsedSyncContent | null;
  shouldSendDeliveryReceipt: boolean;
}

export interface SignalProtocolContentAdapter {
  serializeDataMessage(content: DataMessageInput): Uint8Array;
  serializeSentTranscript(input: SentSyncTranscriptInput): Uint8Array;
  serializeReadSync(entries: ReadSyncEntryInput[]): Uint8Array;
  serializeViewOnceOpenSync(input: ViewOnceOpenSyncInput): Uint8Array;
  serializeMediaAttachmentDeleteSync(input: MediaAttachmentDeleteSyncInput): Uint8Array;
  serializeConfigurationSync(input: ConfigurationSyncInput): Uint8Array;
  serializeUsernameStateSync(input: UsernameStateSyncInput): Uint8Array;
  serializeRecipientUsernameSync(input: RecipientUsernameSyncInput): Uint8Array;
  serializeVerificationStateSync(input: VerificationStateSyncInput): Uint8Array;
  serializeTaskNotificationAckSync(input: TaskNotificationAckSyncInput): Uint8Array;
  serializeBlockedRecipientsSync(input: BlockedRecipientsSyncInput): Uint8Array;
  serializeReceipt(type: 'DELIVERY' | 'READ' | 'VIEWED', timestamps: number[]): string;
  serializeTyping(action: 'STARTED' | 'STOPPED', groupId?: string): string;
  serializeNullMessage(): string;
  serializeSenderKeyDistributionText(
    groupId: string,
    distribution: SenderKeyDistributionMessage
  ): string;
  serializeSenderKeyDistributionBytes(
    groupId: string,
    distribution: SenderKeyDistributionMessage
  ): Uint8Array;
  inspectContent(plaintext: string): InspectedSignalProtocolContent;
  areReadReceiptsEnabled(): Promise<boolean>;
  areTypingIndicatorsEnabled(): Promise<boolean>;
  setRelayBatching(active: boolean): void;
}

type JsonObject = Record<string, unknown>;

function parseJsonObject(plaintext: string): JsonObject | null {
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as JsonObject;
    }
  } catch {
    // Ignore malformed payloads in the default adapter.
  }

  return null;
}

function getDataMessage(payload: JsonObject): JsonObject | null {
  const dataMessage = payload.dataMessage;
  if (dataMessage && typeof dataMessage === 'object' && !Array.isArray(dataMessage)) {
    return dataMessage as JsonObject;
  }

  return null;
}

function isMediaAttachmentCleanupReason(value: unknown): value is MediaAttachmentCleanupReason {
  return (
    value === MediaAttachmentCleanupReason.ViewOnceOpened ||
    value === MediaAttachmentCleanupReason.MessageDeleted ||
    value === MediaAttachmentCleanupReason.MessageExpired ||
    value === MediaAttachmentCleanupReason.OrphanedUpload
  );
}

function inspectPayload(payload: JsonObject): InspectedSignalProtocolContent {
  const dataMessage = getDataMessage(payload);
  const timestamp = dataMessage?.timestamp;
  const mediaTimestamp =
    payload.type === MediaAttachmentMessageType.Attachment &&
    payload.version === 1 &&
    payload.attachment &&
    typeof payload.attachment === 'object' &&
    !Array.isArray(payload.attachment) &&
    typeof payload.timestamp === 'number'
      ? payload.timestamp
      : undefined;

  const receiptMessage = payload.receiptMessage;
  let receipt: ParsedReceiptContent | null = null;
  if (receiptMessage && typeof receiptMessage === 'object' && !Array.isArray(receiptMessage)) {
    const type = (receiptMessage as JsonObject).type;
    const timestamps = (receiptMessage as JsonObject).timestamps;
    if (typeof type === 'string' && Array.isArray(timestamps)) {
      receipt = {
        type,
        timestamps: timestamps.filter((value): value is number => typeof value === 'number'),
      };
    }
  }

  const typingMessage = payload.typingMessage;
  let typing: ParsedTypingContent | null = null;
  if (typingMessage && typeof typingMessage === 'object' && !Array.isArray(typingMessage)) {
    const action = (typingMessage as JsonObject).action;
    const groupId = (typingMessage as JsonObject).groupId;
    if (typeof action === 'string') {
      typing = {
        action,
        groupId: typeof groupId === 'string' ? groupId : undefined,
      };
    }
  }

  const syncMessage = payload.syncMessage;
  let sync: ParsedSyncContent | null = null;
  let conversationId: string | undefined;
  let resolvedTimestamp =
    typeof timestamp === 'number'
      ? timestamp
      : typeof mediaTimestamp === 'number'
        ? mediaTimestamp
        : undefined;
  if (syncMessage && typeof syncMessage === 'object' && !Array.isArray(syncMessage)) {
    const type = (syncMessage as JsonObject).type;
    const sent = (syncMessage as JsonObject).sent;
    if (
      type === 'sent' &&
      sent &&
      typeof sent === 'object' &&
      !Array.isArray(sent) &&
      typeof (sent as JsonObject).conversationId === 'string' &&
      typeof (sent as JsonObject).timestamp === 'number'
    ) {
      conversationId = (sent as JsonObject).conversationId as string;
      resolvedTimestamp = (sent as JsonObject).timestamp as number;
      sync = {
        type: 'sent',
        conversationId,
        timestamp: resolvedTimestamp,
        recipientUserId:
          typeof (sent as JsonObject).recipientUserId === 'string'
            ? ((sent as JsonObject).recipientUserId as string)
            : undefined,
      };
    } else if (type === 'read') {
      sync = {
        type: 'read',
      };
    } else if (
      type === 'viewOnceOpen' &&
      (syncMessage as JsonObject).viewOnceOpen &&
      typeof (syncMessage as JsonObject).viewOnceOpen === 'object' &&
      !Array.isArray((syncMessage as JsonObject).viewOnceOpen)
    ) {
      const viewOnceOpen = (syncMessage as JsonObject).viewOnceOpen as JsonObject;
      if (typeof viewOnceOpen.timestamp === 'number') {
        sync = {
          type: 'viewOnceOpen',
          timestamp: viewOnceOpen.timestamp,
        };
      }
    } else if (
      type === 'mediaAttachmentDelete' &&
      (syncMessage as JsonObject).mediaAttachmentDelete &&
      typeof (syncMessage as JsonObject).mediaAttachmentDelete === 'object' &&
      !Array.isArray((syncMessage as JsonObject).mediaAttachmentDelete)
    ) {
      const mediaAttachmentDelete = (syncMessage as JsonObject).mediaAttachmentDelete as JsonObject;
      if (
        typeof mediaAttachmentDelete.storageId === 'string' &&
        typeof mediaAttachmentDelete.attachmentId === 'string' &&
        isMediaAttachmentCleanupReason(mediaAttachmentDelete.reason) &&
        typeof mediaAttachmentDelete.deletedAt === 'number'
      ) {
        sync = {
          type: 'mediaAttachmentDelete',
          timestamp: mediaAttachmentDelete.deletedAt,
          storageId: mediaAttachmentDelete.storageId,
          attachmentId: mediaAttachmentDelete.attachmentId,
          reason: mediaAttachmentDelete.reason,
        };
      }
    } else if (
      type === 'configuration' &&
      (syncMessage as JsonObject).configuration &&
      typeof (syncMessage as JsonObject).configuration === 'object' &&
      !Array.isArray((syncMessage as JsonObject).configuration)
    ) {
      const configuration = (syncMessage as JsonObject).configuration as JsonObject;
      if (
        typeof configuration.readReceipts === 'boolean' &&
        typeof configuration.typingIndicators === 'boolean'
      ) {
        sync = {
          type: 'configuration',
        };
      }
    } else if (
      type === 'usernameState' &&
      (syncMessage as JsonObject).usernameState &&
      typeof (syncMessage as JsonObject).usernameState === 'object' &&
      !Array.isArray((syncMessage as JsonObject).usernameState)
    ) {
      const usernameState = (syncMessage as JsonObject).usernameState as JsonObject;
      const link = usernameState.link;
      const linkIsValid =
        link === null ||
        (link &&
          typeof link === 'object' &&
          !Array.isArray(link) &&
          typeof (link as JsonObject).entropy === 'string' &&
          typeof (link as JsonObject).handle === 'string');
      if (
        (usernameState.username === null || typeof usernameState.username === 'string') &&
        linkIsValid &&
        (usernameState.username !== null || link === null)
      ) {
        sync = {
          type: 'usernameState',
        };
      }
    } else if (
      type === 'recipientUsername' &&
      (syncMessage as JsonObject).recipientUsername &&
      typeof (syncMessage as JsonObject).recipientUsername === 'object' &&
      !Array.isArray((syncMessage as JsonObject).recipientUsername)
    ) {
      const recipientUsername = (syncMessage as JsonObject).recipientUsername as JsonObject;
      if (
        typeof recipientUsername.userId === 'string' &&
        (recipientUsername.username === null || typeof recipientUsername.username === 'string') &&
        (recipientUsername.uuid === undefined ||
          recipientUsername.uuid === null ||
          typeof recipientUsername.uuid === 'string') &&
        typeof recipientUsername.learnedAt === 'number'
      ) {
        sync = {
          type: 'recipientUsername',
          timestamp: recipientUsername.learnedAt,
          userId: recipientUsername.userId,
        };
      }
    } else if (
      type === 'verificationState' &&
      (syncMessage as JsonObject).verificationState &&
      typeof (syncMessage as JsonObject).verificationState === 'object' &&
      !Array.isArray((syncMessage as JsonObject).verificationState)
    ) {
      const verificationState = (syncMessage as JsonObject).verificationState as JsonObject;
      const state = verificationState.state;
      if (
        typeof verificationState.targetUserId === 'string' &&
        typeof verificationState.identityKey === 'string' &&
        typeof verificationState.changedAt === 'number' &&
        (state === 'default' || state === 'verified')
      ) {
        sync = {
          type: 'verificationState',
          timestamp: verificationState.changedAt,
          targetUserId: verificationState.targetUserId,
        };
      }
    } else if (
      type === 'taskNotificationAck' &&
      (syncMessage as JsonObject).taskNotificationAck &&
      typeof (syncMessage as JsonObject).taskNotificationAck === 'object' &&
      !Array.isArray((syncMessage as JsonObject).taskNotificationAck)
    ) {
      const taskNotificationAck = (syncMessage as JsonObject).taskNotificationAck as JsonObject;
      const taskIds = taskNotificationAck.taskIds;
      const reason = taskNotificationAck.reason;
      if (
        Array.isArray(taskIds) &&
        taskIds.every((value) => typeof value === 'string') &&
        typeof taskNotificationAck.acknowledgedAt === 'number' &&
        typeof taskNotificationAck.acknowledgedOnDevice === 'number' &&
        (reason === 'dismissed' || reason === 'viewed' || reason === 'actioned')
      ) {
        sync = {
          type: 'taskNotificationAck',
          timestamp: taskNotificationAck.acknowledgedAt,
        };
      }
    } else if (
      type === 'blocked' &&
      (syncMessage as JsonObject).blocked &&
      typeof (syncMessage as JsonObject).blocked === 'object' &&
      !Array.isArray((syncMessage as JsonObject).blocked)
    ) {
      const blocked = (syncMessage as JsonObject).blocked as JsonObject;
      const recipients = blocked.recipients;
      if (
        Array.isArray(recipients) &&
        recipients.every(
          (value) =>
            value &&
            typeof value === 'object' &&
            typeof (value as JsonObject).recipientId === 'string' &&
            typeof (value as JsonObject).blockedAt === 'number'
        ) &&
        typeof blocked.syncedAt === 'number'
      ) {
        sync = {
          type: 'blocked',
          timestamp: blocked.syncedAt,
        };
      }
    }
  }

  return {
    timestamp: resolvedTimestamp,
    conversationId,
    receipt,
    typing,
    sync,
    shouldSendDeliveryReceipt: Boolean(dataMessage?.message || dataMessage?.taskComment),
  };
}

export function createDefaultSignalProtocolContentAdapter(): SignalProtocolContentAdapter {
  return {
    serializeDataMessage(content) {
      return new TextEncoder().encode(
        JSON.stringify({
          dataMessage: content,
        })
      );
    },

    serializeSentTranscript(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'sent',
            sent: {
              conversationId: input.conversationId,
              recipientUserId: input.recipientUserId,
              timestamp: input.timestamp,
              serializedContent: CryptoUtils.bytesToBase64(input.serializedContent),
            },
          },
        })
      );
    },

    serializeReadSync(entries) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'read',
            read: entries.map((entry) => ({
              senderUserId: entry.senderUserId,
              timestamp: entry.timestamp,
            })),
          },
        })
      );
    },

    serializeViewOnceOpenSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'viewOnceOpen',
            viewOnceOpen: {
              senderUserId: input.senderUserId,
              timestamp: input.timestamp,
            },
          },
        })
      );
    },

    serializeMediaAttachmentDeleteSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'mediaAttachmentDelete',
            mediaAttachmentDelete: {
              storageId: input.storageId,
              attachmentId: input.attachmentId,
              reason: input.reason,
              deletedAt: input.deletedAt,
            },
          },
        })
      );
    },

    serializeConfigurationSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'configuration',
            configuration: {
              readReceipts: input.readReceipts,
              typingIndicators: input.typingIndicators,
            },
          },
        })
      );
    },

    serializeUsernameStateSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'usernameState',
            usernameState: {
              username: input.username,
              link: input.link,
            },
          },
        })
      );
    },

    serializeRecipientUsernameSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'recipientUsername',
            recipientUsername: {
              userId: input.userId,
              username: input.username,
              ...(input.uuid !== undefined ? { uuid: input.uuid } : {}),
              learnedAt: input.learnedAt,
            },
          },
        })
      );
    },

    serializeVerificationStateSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'verificationState',
            verificationState: {
              targetUserId: input.targetUserId,
              identityKey: input.identityKey,
              state: input.state,
              changedAt: input.changedAt,
            },
          },
        })
      );
    },

    serializeTaskNotificationAckSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'taskNotificationAck',
            taskNotificationAck: {
              taskIds: input.taskIds,
              acknowledgedAt: input.acknowledgedAt,
              acknowledgedOnDevice: input.acknowledgedOnDevice,
              reason: input.reason,
            },
          },
        })
      );
    },

    serializeBlockedRecipientsSync(input) {
      return new TextEncoder().encode(
        JSON.stringify({
          syncMessage: {
            type: 'blocked',
            blocked: {
              recipients: input.recipients,
              syncedAt: input.syncedAt,
            },
          },
        })
      );
    },

    serializeReceipt(type, timestamps) {
      return JSON.stringify({
        receiptMessage: {
          type,
          timestamps,
        },
      });
    },

    serializeTyping(action, groupId) {
      return JSON.stringify({
        typingMessage: {
          action,
          ...(groupId ? { groupId } : {}),
        },
      });
    },

    serializeNullMessage() {
      return JSON.stringify({
        nullMessage: {},
      });
    },

    serializeSenderKeyDistributionText(groupId, distribution) {
      return JSON.stringify({
        senderKeyDistributionMessage: JSON.stringify({
          groupId,
          ...distribution,
        }),
      });
    },

    serializeSenderKeyDistributionBytes(groupId, distribution) {
      return new TextEncoder().encode(
        this.serializeSenderKeyDistributionText(groupId, distribution)
      );
    },

    inspectContent(plaintext) {
      const payload = parseJsonObject(plaintext);
      if (!payload) {
        return {
          timestamp: undefined,
          conversationId: undefined,
          receipt: null,
          typing: null,
          sync: null,
          shouldSendDeliveryReceipt: false,
        };
      }

      return inspectPayload(payload);
    },

    async areReadReceiptsEnabled() {
      return true;
    },

    async areTypingIndicatorsEnabled() {
      return true;
    },

    setRelayBatching() {
      // No-op for the protocol-default adapter.
    },
  };
}
