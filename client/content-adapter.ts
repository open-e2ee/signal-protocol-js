import type { SenderKeyDistributionMessage } from '../internal/protocol/sender-keys';
import type { DataMessageInput } from './types';
import * as CryptoUtils from '../internal/crypto';
import { utf8Decode } from '../internal/platform';
import { asBase64 } from '../types/utils';
import {
  parseSenderKeyDistribution,
  type ParsedSenderKeyDistribution,
} from './sender-key-distribution';
import { PROFILE_KEY_UPDATE_FLAG } from './profile-key-exchange';
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

/**
 * The sync content that `inspectContent` reads from a plaintext.
 *
 * The next major SDK version adds the `type` member `'groupKeySync'`. Code
 * that switches on `type` must handle it in that version.
 */
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

/**
 * The context of a managed group inside the encrypted content of each
 * message to the group, as Signal's `GroupContextV2`. The receiver derives
 * the group ID from the master key and brings its group state up to the
 * revision before it authorizes the content.
 */
export interface GroupContentContext {
  /** The group master key. It is 32 bytes. */
  masterKey: Uint8Array;
  /** The revision of the sender's verified group state at the send. */
  revision: number;
  /** A signed group change to this revision, when the content carries one. */
  groupChange?: Uint8Array;
}

export interface InspectedSignalProtocolContent {
  senderKeyDistribution?: ParsedSenderKeyDistribution;
  /**
   * The managed group context of the content, or of the content inside a
   * sent-sync transcript. `'malformed'` when a context is present but does
   * not decode. Absent when the content has no context. A custom adapter
   * must report it for its own context encoding.
   */
  groupContext?: GroupContentContext | 'malformed';
  /**
   * True when the content carries a sender key distribution and nothing
   * else. The client installs a distribution in either case. It consumes a
   * distribution-only content. Content beside a distribution, such as a
   * data message, continues to the receipt, typing or data handling. A
   * custom adapter must report it for its own distribution encoding.
   */
  senderKeyDistributionOnly: boolean;
  timestamp?: number;
  conversationId?: string;
  receipt: ParsedReceiptContent | null;
  typing: ParsedTypingContent | null;
  sync: ParsedSyncContent | null;
  shouldSendDeliveryReceipt: boolean;
  /** The sender's profile key, from `dataMessage.profileKey`, as standard base64. */
  profileKey?: string;
  /** True for a DataMessage with the Signal `PROFILE_KEY_UPDATE` flag. */
  profileKeyUpdate?: boolean;
  /**
   * True for a null message. A sender answers a retry request with one
   * when it no longer has the plaintext. A null message carries no
   * content. The client consumes a null message when the content adapter
   * reports `nullMessage: true`, and never gives it to the application.
   * A custom adapter must report it for its own null encoding.
   */
  nullMessage: boolean;
}

/**
 * Serializes the content that the client sends, and inspects the content
 * that it receives.
 *
 * The next major SDK version adds the required method
 * `serializeGroupKeySync`, so a custom adapter must implement it in that
 * version. An adapter that spreads the result of
 * `createDefaultSignalProtocolContentAdapter()` into itself gets the default
 * method. Upgrade every own device of one account in one release: an own
 * device on an older SDK version gives the raw group key sync to
 * `onMessageDecrypted`.
 */
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
  /**
   * The logged content of a group message with a sender-key distribution
   * beside it, in one payload. A sender answers a retry request for a group
   * message with it, so the requesting device gets the content and the
   * current sender key of the group in one resend. `inspectContent` must
   * report the distribution of the result, and the result must give the
   * content to the application as the original message.
   *
   * @param content - The plaintext of the group message, as the send logged it
   * @param groupId - The raw group ID
   * @param distribution - The current sender-key distribution of the sender
   * @throws Error when the content cannot carry a distribution
   */
  serializeContentBesideSenderKeyDistribution(
    content: string,
    groupId: string,
    distribution: SenderKeyDistributionMessage
  ): string;
  /**
   * The plaintext that a pairwise message record keeps, with no sender-key
   * distribution in it. A distribution holds the chain key of a group
   * sender key, and that key rests only in the sender key store.
   *
   * Return the plaintext unchanged when it carries no distribution. Return
   * the other content when a distribution travels beside it, so the record
   * stays resendable. Return null when the distribution is all it carries.
   * Apply the same rule to the content inside a sent-sync transcript in
   * this adapter's format, because the client syncs a sent distribution to
   * its other devices.
   *
   * @param plaintext - The plaintext of a pairwise send
   * @returns The plaintext to keep, or null to keep no record
   */
  withoutSenderKeyDistribution(plaintext: string): string | null;
  /**
   * The content of a managed group message with the group context in it.
   * The client calls it once for each new send to a managed group, and the
   * sent-sync transcript and each resend carry the result. Every content
   * must be able to carry a context. `inspectContent` must report the
   * context of the result, and `withoutGroupContext` must give the content
   * back.
   *
   * @param content - The content that the application sends
   * @param context - The context of the group at the send
   */
  serializeContentWithGroupContext(
    content: Uint8Array,
    context: GroupContentContext
  ): Uint8Array;
  /**
   * The content that the application gets, with no group context in it.
   * Return the plaintext unchanged when it carries no context. Apply the
   * same rule to the content inside a sent-sync transcript in this
   * adapter's format.
   *
   * @param plaintext - The decrypted plaintext
   */
  withoutGroupContext(plaintext: string): string;
  inspectContent(plaintext: string): InspectedSignalProtocolContent;
  areReadReceiptsEnabled(): Promise<boolean>;
  areTypingIndicatorsEnabled(): Promise<boolean>;
  setRelayBatching(active: boolean): void;
}

type JsonObject = Record<string, unknown>;

/** The `sent` member of a sent-sync transcript in the default format. */
function sentTranscriptOf(payload: JsonObject): JsonObject | null {
  const syncMessage = payload.syncMessage;
  if (!syncMessage || typeof syncMessage !== 'object' || Array.isArray(syncMessage)) return null;
  const { type, sent } = syncMessage as JsonObject;
  if (type !== 'sent' || !sent || typeof sent !== 'object' || Array.isArray(sent)) return null;
  return typeof (sent as JsonObject).serializedContent === 'string' ? (sent as JsonObject) : null;
}

/** The UTF-8 text of base64 content, or null when it is not both. */
function decodedContent(serializedContent: string): string | null {
  try {
    return utf8Decode(CryptoUtils.base64ToBytes(asBase64(serializedContent)), { fatal: true });
  } catch {
    return null;
  }
}

// The default format keeps the group context in the `groupContext` member
// of a JSON object content. Content of another form travels as the
// `groupContent` member beside it, so the application gets its bytes back.
const GROUP_CONTEXT = 'groupContext';
const GROUP_CONTENT = 'groupContent';

/**
 * The text of decrypted bytes, as the cipher gives a plaintext: the UTF-8
 * text when it round-trips to the same bytes, otherwise base64.
 */
function losslessText(bytes: Uint8Array): string {
  const text = utf8Decode(bytes);
  const roundTrip = new TextEncoder().encode(text);
  if (
    roundTrip.length === bytes.length &&
    roundTrip.every((byte, index) => byte === bytes[index])
  ) {
    return text;
  }
  return CryptoUtils.bytesToBase64(bytes);
}

function decodeBase64(value: unknown): Uint8Array | null {
  if (typeof value !== 'string') return null;
  try {
    return CryptoUtils.base64ToBytes(asBase64(value));
  } catch {
    return null;
  }
}

function encodeGroupContext(context: GroupContentContext): JsonObject {
  return {
    masterKey: CryptoUtils.bytesToBase64(context.masterKey),
    revision: context.revision,
    ...(context.groupChange && {
      groupChange: CryptoUtils.bytesToBase64(context.groupChange),
    }),
  };
}

function decodeGroupContext(value: unknown): GroupContentContext | 'malformed' {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'malformed';
  const { masterKey, revision, groupChange } = value as JsonObject;
  const key = decodeBase64(masterKey);
  const change = groupChange === undefined ? undefined : decodeBase64(groupChange);
  if (!key || typeof revision !== 'number' || change === null) return 'malformed';
  return { masterKey: key, revision, ...(change && { groupChange: change }) };
}

/**
 * The application content of a payload with a group context: the bytes of
 * its `groupContent` member, or the object with no context in it. Null when
 * the `groupContent` member does not decode.
 */
function contentBesideGroupContext(payload: JsonObject): Uint8Array | null {
  if (GROUP_CONTENT in payload) return decodeBase64(payload[GROUP_CONTENT]);
  const { [GROUP_CONTEXT]: _context, ...content } = payload;
  return new TextEncoder().encode(JSON.stringify(content));
}

/** The group context of a payload, or of the content inside its sent-sync transcript. */
function groupContextOf(payload: JsonObject): GroupContentContext | 'malformed' | undefined {
  const sent = sentTranscriptOf(payload);
  const inner = sent && decodedContent(sent.serializedContent as string);
  const carrier = inner === null || inner === undefined ? payload : parseJsonObject(inner);
  if (!carrier || !(GROUP_CONTEXT in carrier)) return undefined;
  if (contentBesideGroupContext(carrier) === null) return 'malformed';
  return decodeGroupContext(carrier[GROUP_CONTEXT]);
}

/** The default format of `serializeContentWithGroupContext`. */
function withGroupContext(content: Uint8Array, context: GroupContentContext): Uint8Array {
  const encoded = encodeGroupContext(context);
  const payload = (() => {
    try {
      return parseJsonObject(utf8Decode(content, { fatal: true }));
    } catch {
      return null;
    }
  })();
  const inPlace =
    payload !== null &&
    !(GROUP_CONTEXT in payload) &&
    !(GROUP_CONTENT in payload) &&
    losslessText(content) === JSON.stringify(payload);
  return new TextEncoder().encode(
    JSON.stringify(
      inPlace
        ? { ...payload, [GROUP_CONTEXT]: encoded }
        : { [GROUP_CONTEXT]: encoded, [GROUP_CONTENT]: CryptoUtils.bytesToBase64(content) }
    )
  );
}

/** The default format of `withoutGroupContext`. */
function withoutGroupContext(plaintext: string): string {
  const payload = parseJsonObject(plaintext);
  if (!payload) return plaintext;
  if (GROUP_CONTEXT in payload) {
    const content = contentBesideGroupContext(payload);
    return content ? losslessText(content) : plaintext;
  }
  const sent = sentTranscriptOf(payload);
  const inner = sent && decodedContent(sent.serializedContent as string);
  const innerPayload = inner === null || inner === undefined ? null : parseJsonObject(inner);
  if (!sent || !innerPayload || !(GROUP_CONTEXT in innerPayload)) return plaintext;
  const content = contentBesideGroupContext(innerPayload);
  if (content === null) return plaintext;
  return JSON.stringify({
    ...payload,
    syncMessage: {
      ...(payload.syncMessage as JsonObject),
      sent: {
        ...sent,
        serializedContent: CryptoUtils.bytesToBase64(content),
      },
    },
  });
}

/**
 * The default format of `withoutSenderKeyDistribution`. The distribution is
 * the `senderKeyDistributionMessage` member of the content, or of the
 * content inside a sent-sync transcript.
 */
function withoutSenderKeyDistribution(plaintext: string): string | null {
  const payload = parseJsonObject(plaintext);
  if (!payload) return plaintext;
  if ('senderKeyDistributionMessage' in payload) {
    const { senderKeyDistributionMessage: _distribution, ...content } = payload;
    return Object.keys(content).length === 0 ? null : JSON.stringify(content);
  }
  const sent = sentTranscriptOf(payload);
  const inner = sent && decodedContent(sent.serializedContent as string);
  if (!sent || inner === null) return plaintext;
  const kept = withoutSenderKeyDistribution(inner);
  if (kept === inner) return plaintext;
  if (kept === null) return null;
  return JSON.stringify({
    ...payload,
    syncMessage: {
      ...(payload.syncMessage as JsonObject),
      sent: {
        ...sent,
        serializedContent: CryptoUtils.bytesToBase64(new TextEncoder().encode(kept)),
      },
    },
  });
}

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

function emptyInspection(): InspectedSignalProtocolContent {
  return {
    timestamp: undefined,
    conversationId: undefined,
    receipt: null,
    typing: null,
    sync: null,
    shouldSendDeliveryReceipt: false,
    senderKeyDistributionOnly: false,
    nullMessage: false,
  };
}

function inspectText(plaintext: string): InspectedSignalProtocolContent {
  const payload = parseJsonObject(plaintext);
  return payload ? inspectPayload(payload) : emptyInspection();
}

function inspectPayload(payload: JsonObject): InspectedSignalProtocolContent {
  const groupContext = groupContextOf(payload);
  if (GROUP_CONTEXT in payload && GROUP_CONTENT in payload) {
    // The content travels beside the context. Its own inspection gives
    // everything but the context, and a distribution that a resend put
    // beside both.
    const content = contentBesideGroupContext(payload);
    const { groupContext: _inner, ...inspected } = content
      ? inspectText(losslessText(content))
      : emptyInspection();
    return {
      ...inspected,
      ...('senderKeyDistributionMessage' in payload && {
        senderKeyDistribution: parseSenderKeyDistribution(payload.senderKeyDistributionMessage),
        senderKeyDistributionOnly: false,
      }),
      groupContext: groupContext!,
    };
  }
  const dataMessage = getDataMessage(payload);
  const timestamp = dataMessage?.timestamp;
  const profileKey = dataMessage?.profileKey;
  const flags = dataMessage?.flags;
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
    ...('senderKeyDistributionMessage' in payload
      ? { senderKeyDistribution: parseSenderKeyDistribution(payload.senderKeyDistributionMessage) }
      : {}),
    senderKeyDistributionOnly:
      'senderKeyDistributionMessage' in payload && Object.keys(payload).length === 1,
    receipt,
    typing,
    sync,
    shouldSendDeliveryReceipt: Boolean(dataMessage?.message || dataMessage?.taskComment),
    ...(typeof profileKey === 'string' ? { profileKey } : {}),
    ...(typeof flags === 'number' && (flags & PROFILE_KEY_UPDATE_FLAG) !== 0
      ? { profileKeyUpdate: true }
      : {}),
    nullMessage: Boolean(
      payload.nullMessage &&
        typeof payload.nullMessage === 'object' &&
        !Array.isArray(payload.nullMessage)
    ),
    ...(groupContext !== undefined && { groupContext }),
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

    serializeContentBesideSenderKeyDistribution(content, groupId, distribution) {
      const payload = parseJsonObject(content);
      if (!payload) {
        throw new Error('The content of a group message is not a JSON object');
      }
      return JSON.stringify({
        ...payload,
        senderKeyDistributionMessage: JSON.stringify({ groupId, ...distribution }),
      });
    },

    withoutSenderKeyDistribution(plaintext) {
      return withoutSenderKeyDistribution(plaintext);
    },

    serializeContentWithGroupContext(content, context) {
      return withGroupContext(content, context);
    },

    withoutGroupContext(plaintext) {
      return withoutGroupContext(plaintext);
    },

    inspectContent(plaintext) {
      return inspectText(plaintext);
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
