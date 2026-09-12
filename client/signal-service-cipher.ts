/**
 * SignalProtocolServiceCipher - Cipher coordination for Signal Protocol
 *
 * @layer 1 - API
 *
 * Public coordination surface:
 * - `decrypt(envelope)` → DecryptedEnvelope
 * - `encrypt(recipientId, content)` → SendResult
 *
 * Separates cipher coordination (encrypt/decrypt routing) from lifecycle
 * management (sessions, keys, hooks, subscriptions) in SignalProtocolClient.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import AsyncLock from 'async-lock';
import type {
  ISignalProtocolRelayServer,
  Envelope,
  StaleSessionErrorData,
  SealedSenderAuth,
  GroupMemberDevice,
} from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { ISignalProtocolLocalStore, Base64 } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import { base64ToBytes } from '../internal/crypto';
import type { DecryptedEnvelope } from './event-hooks';
import { recordServerClockSample } from '../server-clock';
import { ProtocolAddress } from '../types/address';
import type { ISesameManager, SesameMessage, OutgoingMessageBatch } from '../internal/sesame/types';
import { defaultSignalProtocolLogger, type ILogger } from '../logger';
import { SenderKeyManager } from '../internal/protocol/sender-keys';
import { isGroupId, extractGroupId } from '../internal/groups';
import type { EndorsementManager } from './endorsement-manager';
import type { PreparedAttachmentUpload, SendOptions, SendResult } from './types';
import { ContentHint } from '../types/messages';
import { SealedSenderContentType } from '../internal/protocol/sealed-sender/types';
import {
  type BlockedRecipientsSyncInput,
  createDefaultSignalProtocolContentAdapter,
  type ConfigurationSyncInput,
  type MediaAttachmentDeleteSyncInput,
  type ReadSyncEntryInput,
  type RecipientUsernameSyncInput,
  type SignalProtocolContentAdapter,
  type TaskNotificationAckSyncInput,
  type UsernameStateSyncInput,
  type VerificationStateSyncInput,
  type ViewOnceOpenSyncInput,
} from './content-adapter';
import * as CryptoUtils from '../internal/crypto';
import {
  completeOutgoingMessageIntent,
  getOutgoingMessageIntent,
  replaceOutgoingDirectDeviceMessage,
  storeOutgoingMessageIntent,
  withOutgoingMessageIntentLock,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import { withRetry } from '../utils/retry';
import { prepareGroupSharedMessage } from './group-sealed-sender';
import { sendGroupWithExactOutbox } from './group-outbox';
import {
  resolveSealedSenderContext as resolveSealedSenderSendContext,
  serializeDirectSealedSenderMessage as serializeDirectSealedSenderTransport,
  type ResolvedSealedSenderContext,
  type SealedSenderProvider as SealedSenderProviderContract,
} from './sealed-sender';
import { prepareMediaAttachmentUpload, serializeMediaAttachmentMessage } from '../media';
import {
  UnidentifiedAccessMode,
  type ContactProfileStateStore,
  type UnidentifiedAccessModeType,
} from '../profile/contact-state';

/**
 * Sort envelopes so PreKeyMessages are processed first
 *
 * PreKeyMessages establish new sessions, so they must be processed before
 * ciphertexts that depend on those sessions. That order keeps SESAME session
 * convergence correct.
 *
 * @param envelopes - Array of encrypted envelopes to sort
 * @returns New sorted array (does not mutate input)
 *
 * @internal Used by SignalProtocolClient.processIncomingEnvelopes and background sync
 * @see https://signal.org/docs/specifications/sesame/ Section 3.4
 */
export {};
export function sortEnvelopesForDecryption<T extends { messageType?: string }>(
  envelopes: T[]
): T[] {
  return [...envelopes].sort((a, b) => {
    // Treat undefined messageType as non-prekey (ciphertext comes after prekey_bundle)
    const aIsPreKey = a.messageType === 'prekey_bundle' ? 0 : 1;
    const bIsPreKey = b.messageType === 'prekey_bundle' ? 0 : 1;
    return aIsPreKey - bIsPreKey;
  });
}

/**
 * Detect actual message type from ciphertext for envelope metadata
 *
 * PreKeyMessages (first messages) should have messageType: 'prekey_bundle'
 * Regular ratchet messages should have messageType: 'ciphertext'
 *
 * @param ciphertext - The encrypted message content (string or Uint8Array)
 * @returns 'prekey_bundle' for PreKeyMessages, 'ciphertext' for regular messages
 */
function getEnvelopeMessageType(ciphertext: string | Uint8Array): 'prekey_bundle' | 'ciphertext' {
  const text = typeof ciphertext === 'string' ? ciphertext : new TextDecoder().decode(ciphertext);

  // Binary protobuf format: base64 decode, check first protobuf tag
  try {
    const bytes = CryptoUtils.base64ToBytes(text as Base64);
    if (bytes.length >= 2) {
      const firstTag = bytes[1];
      // PreKeySignalProtocolMessage: first tag is 0x08 (field 1 uint32) or 0x12 (field 2 bytes)
      if (firstTag === 0x08 || firstTag === 0x12) {
        return 'prekey_bundle';
      }
    }
  } catch {
    // Not valid base64 binary
  }

  return 'ciphertext';
}

function attachClientMessageId(error: unknown, clientMessageId: string): Error {
  const normalized = error instanceof Error ? error : new Error(String(error));
  try {
    Object.defineProperty(normalized, 'clientMessageId', {
      configurable: true,
      enumerable: true,
      value: clientMessageId,
    });
    return normalized;
  } catch {
    const wrapped = new Error(normalized.message);
    wrapped.name = normalized.name;
    Object.defineProperty(wrapped, 'clientMessageId', {
      enumerable: true,
      value: clientMessageId,
    });
    return wrapped;
  }
}

/**
 * Detect if an error is a stale session error from the server
 *
 * The relay returns STALE_DEVICE when a PreKeyMessage uses an outdated
 * registration ID.
 *
 * This SDK validates registration IDs at the relay boundary. Stale-prekey
 * detection remains client-side through authentication failure and retry.
 *
 * @param error - The error to check
 * @returns True if error indicates stale session requiring bundle refresh
 */
function isStaleSessionError(error: unknown): error is { data: StaleSessionErrorData } {
  if (error && typeof error === 'object' && 'data' in error) {
    const data = (error as { data: unknown }).data;
    if (data && typeof data === 'object' && 'code' in data) {
      const code = (data as { code: string }).code;
      return code === 'STALE_DEVICE';
    }
  }
  return false;
}

class SealedSenderRecipientRejectedError extends Error {
  constructor() {
    super('Sealed sender recipient was not accepted');
    this.name = 'SealedSenderRecipientRejectedError';
  }
}

function isConclusiveDeviceRejection(error: unknown): boolean {
  return isStaleSessionError(error) || error instanceof SealedSenderRecipientRejectedError;
}

/**
 * Sealed sender context provider callback
 *
 * Provides the sender certificate and identity key pair needed for sealing.
 * Injected by SignalProtocolClient so the cipher does not need to manage certificate
 * caching or key lookup directly.
 *
 * @returns Sender certificate (base64), sender private key (bytes), and config
 */
export type SealedSenderProvider = SealedSenderProviderContract;

/**
 * Callback for establishing sessions when none exist
 * Allows SignalProtocolClient to inject its session establishment logic
 */
export type SessionEstablisher = (recipientUserId: string) => Promise<{
  establishedDevices: number[];
  failedDevices: number[];
  failedDeviceErrors: Array<{ deviceId: number; error: Error }>;
}>;

/**
 * Callback for refreshing a stale session after STALE_DEVICE error
 *
 * Stale-device recovery:
 * 1. Archive the stale session (preserves for delayed message decryption)
 * 2. Fetch fresh prekey bundle from server
 * 3. Establish new session with fresh keys
 *
 * @param recipientUserId - User ID whose session needs refresh
 * @param recipientDeviceId - Device ID that returned stale error
 * @returns True if session was successfully refreshed
 */
export type StaleSessionRefresher = (
  recipientUserId: string,
  recipientDeviceId: number
) => Promise<boolean>;

/**
 * Callback for refreshing group send endorsements before V2 sealed sender send.
 *
 * Called when `shouldRefreshEndorsements()` indicates refresh is needed.
 * The implementation should fetch endorsements from the server and cache them.
 *
 * @param groupId - Group identifier
 * @param memberUserIds - User IDs of all group members to endorse (excluding self)
 * @returns true if endorsements were refreshed, false on failure
 *
 */
export type EndorsementRefresher = (groupId: string, memberUserIds: string[]) => Promise<boolean>;
export type GroupSendBarrierChecker = (groupId: string) => Promise<void>;

/**
 * SignalProtocolServiceCipher - Routes encryption and decryption to appropriate ciphers
 *
 * Handles:
 * - Pairwise messages via SESAME/Double Ratchet
 * - Group messages via Sender Keys
 * - Binary content with two-layer encryption (AES-GCM + Signal Protocol)
 *
 * @example
 * ```typescript
 * // Created by SignalProtocolClient - not instantiated directly
 * const cipher = new SignalProtocolServiceCipher(userId, deviceId, sesameManager, ...);
 *
 * // Decrypt incoming envelope
 * const decrypted = await cipher.decrypt(envelope);
 *
 * // Encrypt outgoing message
 * const result = await cipher.encrypt('bob', 'Hello!');
 * ```
 */
export class SignalProtocolServiceCipher {
  private readonly lock = new AsyncLock();
  private sessionEstablisher?: SessionEstablisher;
  private staleSessionRefresher?: StaleSessionRefresher;
  private sealedSenderProvider?: SealedSenderProvider;
  private sealedSenderDeliveryMode: import('./config').SealedSenderDeliveryMode = 'preferred';
  private sealedSenderIdentifiedFallback?: import('./config').SealedSenderConfig['onIdentifiedFallback'];
  private contactProfileStateStore?: ContactProfileStateStore;
  private endorsementManager?: EndorsementManager;
  private endorsementRefresher?: EndorsementRefresher;
  private groupSendBarrierChecker?: GroupSendBarrierChecker;
  private groupSecretParamsProvider?: (
    groupId: string
  ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>;

  constructor(
    private readonly userId: string,
    private readonly deviceId: number,
    private readonly sesameManager: ISesameManager,
    private readonly senderKeyManager: SenderKeyManager,
    private readonly storage: ISignalProtocolLocalStore,
    private readonly relay?: ISignalProtocolRelayServer,
    private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore,
    private readonly contentAdapter?: SignalProtocolContentAdapter,
    private readonly logger: Required<ILogger> = defaultSignalProtocolLogger
  ) {}

  private getResolvedContentAdapter(): SignalProtocolContentAdapter {
    return this.contentAdapter ?? createDefaultSignalProtocolContentAdapter();
  }

  private getDirectConversationId(recipientUserId: string): string {
    const sortedIds = [this.userId, recipientUserId].sort();
    return `dm:${sortedIds[0]}_${sortedIds[1]}`;
  }

  private buildSentSyncTranscript(
    conversationId: string,
    plaintextBytes: Uint8Array,
    timestamp: number,
    recipientUserId?: string
  ): Uint8Array {
    return this.getResolvedContentAdapter().serializeSentTranscript({
      conversationId,
      serializedContent: plaintextBytes,
      timestamp,
      recipientUserId,
    });
  }

  private encodeLosslessPlaintext(plaintextBytes: Uint8Array): string {
    const text = new TextDecoder().decode(plaintextBytes);
    const roundTrip = new TextEncoder().encode(text);

    if (
      roundTrip.length === plaintextBytes.length &&
      roundTrip.every((byte, index) => byte === plaintextBytes[index])
    ) {
      return text;
    }

    return CryptoUtils.bytesToBase64(plaintextBytes);
  }

  private async uploadSyncMessages(syncMessages: SesameMessage[]): Promise<void> {
    if (!this.relay || syncMessages.length === 0) {
      return;
    }

    for (const syncMsg of syncMessages) {
      await this.relay.send({
        targetUserId: syncMsg.recipientUserId,
        targetDeviceId: syncMsg.recipientDeviceId,
        senderUserId: this.userId,
        senderDeviceId: this.deviceId,
        ciphertext:
          typeof syncMsg.ciphertext === 'string'
            ? syncMsg.ciphertext
            : CryptoUtils.bytesToBase64(syncMsg.ciphertext),
        messageType: getEnvelopeMessageType(syncMsg.ciphertext),
        deliveryClass: 'background-sync',
        timestamp: syncMsg.timestamp,
      });
    }
  }

  private async sendSyncPayloadToLocalOtherDevices(
    payloadBytes: Uint8Array,
    timestamp: number
  ): Promise<void> {
    if (!this.relay) {
      return;
    }

    const syncMessages = await this.sesameManager.sendToLocalOtherDevices(payloadBytes, {
      clientTimestamp: timestamp,
      includeSyncMessages: false,
    });
    await this.uploadSyncMessages(syncMessages);
  }

  async sendReadSyncToLocalOtherDevices(entries: ReadSyncEntryInput[]): Promise<void> {
    if (entries.length === 0) {
      return;
    }

    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeReadSync(entries);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendViewOnceOpenSyncToLocalOtherDevices(entry: ViewOnceOpenSyncInput): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeViewOnceOpenSync(entry);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendMediaAttachmentDeleteSyncToLocalOtherDevices(
    entry: MediaAttachmentDeleteSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeMediaAttachmentDeleteSync(entry);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, entry.deletedAt);
  }

  async sendConfigurationSyncToLocalOtherDevices(
    configuration: ConfigurationSyncInput
  ): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeConfigurationSync(configuration);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendUsernameStateSyncToLocalOtherDevices(
    usernameState: UsernameStateSyncInput
  ): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeUsernameStateSync(usernameState);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendRecipientUsernameSyncToLocalOtherDevices(
    recipientUsername: RecipientUsernameSyncInput
  ): Promise<void> {
    const payloadBytes =
      this.getResolvedContentAdapter().serializeRecipientUsernameSync(recipientUsername);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, recipientUsername.learnedAt);
  }

  async sendVerificationStateSyncToLocalOtherDevices(
    verificationState: VerificationStateSyncInput
  ): Promise<void> {
    const payloadBytes =
      this.getResolvedContentAdapter().serializeVerificationStateSync(verificationState);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, verificationState.changedAt);
  }

  async sendTaskNotificationAckSyncToLocalOtherDevices(
    ack: TaskNotificationAckSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeTaskNotificationAckSync(ack);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, ack.acknowledgedAt);
  }

  async sendBlockedRecipientsSyncToLocalOtherDevices(
    blocked: BlockedRecipientsSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeBlockedRecipientsSync(blocked);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, blocked.syncedAt);
  }

  /**
   * Set the session establisher callback
   * Called by SignalProtocolClient after construction to inject session establishment logic
   */
  setSessionEstablisher(establisher: SessionEstablisher): void {
    this.sessionEstablisher = establisher;
  }

  /**
   * Set the stale session refresher callback
   * Called by SignalProtocolClient after construction to inject session refresh logic
   *
   * Used when server returns STALE_DEVICE errors (device reinstalled).
   */
  setStaleSessionRefresher(refresher: StaleSessionRefresher): void {
    this.staleSessionRefresher = refresher;
  }

  /**
   * Set the sealed sender provider callback
   * Called by SignalProtocolClient after construction to inject sealed sender support.
   *
   * Provides the sender certificate and identity key needed for sealing messages.
   */
  setSealedSenderProvider(provider: SealedSenderProvider): void {
    this.sealedSenderProvider = provider;
  }

  setSealedSenderDeliveryMode(mode: import('./config').SealedSenderDeliveryMode): void {
    this.sealedSenderDeliveryMode = mode;
  }

  setSealedSenderIdentifiedFallback(
    callback: NonNullable<import('./config').SealedSenderConfig['onIdentifiedFallback']>
  ): void {
    this.sealedSenderIdentifiedFallback = callback;
  }

  private async reportIdentifiedFallback(recipientUserId: string): Promise<void> {
    try {
      await this.sealedSenderIdentifiedFallback?.({
        recipientUserId,
        reason: 'authorization-rejected',
      });
    } catch (fallbackHookError) {
      this.logger.warn('Sealed sender identified-fallback hook failed', {
        category: 'E2EE',
        data: {
          recipientUserId,
          error: (fallbackHookError as Error).message,
        },
      });
    }
  }

  private useIdentifiedDeliveryOrThrow(recipientUserId: string, reason: string): null {
    if (this.sealedSenderDeliveryMode === 'required') {
      throw new EncryptionError(
        `Sealed sender is required but unavailable: ${reason}`,
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { recipientUserId, operation: 'resolveSealedSenderContext', reason }
      );
    }
    return null;
  }

  setContactProfileStateStore(store: ContactProfileStateStore): void {
    this.contactProfileStateStore = store;
  }

  /**
   * Set the endorsement manager for group send endorsement-based auth.
   *
   * When set, group messages will prefer endorsement tokens over UAK-based
   * sealed sender. This avoids needing the recipient's profile key for
   * group messages and provides stronger group membership verification.
   *
   */
  setEndorsementManager(manager: EndorsementManager): void {
    this.endorsementManager = manager;
  }

  /**
   * Set the endorsement refresher callback.
   *
   * Called before V2 multi-recipient sends when endorsements are missing or
   * expiring soon. The implementation fetches endorsements from the server
   * and caches them via EndorsementManager.
   *
   */
  setEndorsementRefresher(refresher: EndorsementRefresher): void {
    this.endorsementRefresher = refresher;
  }

  /** Enforce the group-system C7 barrier at the sender-key send boundary. */
  setGroupSendBarrierChecker(checker: GroupSendBarrierChecker): void {
    this.groupSendBarrierChecker = checker;
  }

  /**
   * Set the group secret params provider callback.
   *
   * Required for endorsement-based sealed sender in groups. The provider
   * looks up GroupSecretParams from the local database for a given group ID.
   *
   * @param provider - Async callback returning GroupSecretParams or null
   */
  setGroupSecretParamsProvider(
    provider: (
      groupId: string
    ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>
  ): void {
    this.groupSecretParamsProvider = provider;
  }

  // ============================================================================
  // Public API
  // ============================================================================

  /**
   * Decrypt incoming envelope - routes to appropriate cipher
   *
   * Routes based on envelope type:
   * - ciphertext + groupId → Group cipher (Sender Keys)
   * - otherwise → Pairwise cipher (SESAME/Double Ratchet)
   *
   * @param envelope - Encrypted envelope from relay
   * @returns Decrypted envelope ready for ContentManager
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async decrypt(
    envelope: Envelope,
    sealedSenderConfig?: import('./config').SealedSenderConfig
  ): Promise<DecryptedEnvelope> {
    // Handle sealed sender (unidentified_sender) envelopes by unsealing first
    if (envelope.messageType === 'unidentified_sender') {
      if (!sealedSenderConfig || sealedSenderConfig.trustRoots.length === 0) {
        throw new EncryptionError(
          'Received sealed sender message but no trust roots configured',
          EncryptionErrorCode.INVALID_CIPHERTEXT,
          { messageType: envelope.messageType }
        );
      }

      const { unsealMessage, reconstructEnvelope } = await import('./sealed-sender');

      // Get recipient's X25519 identity private key for unsealing
      const identityKeyPair = await this.storage.getIdentityKey();
      if (!identityKeyPair) {
        throw new EncryptionError(
          'No identity key pair for sealed sender decryption',
          EncryptionErrorCode.DECRYPTION_FAILED
        );
      }

      // Convert branded Base64 private key to Uint8Array for sealed sender
      const recipientPrivateKeyBytes = base64ToBytes(identityKeyPair.dhKey.privateKey);

      const ciphertextStr =
        typeof envelope.ciphertext === 'string'
          ? envelope.ciphertext
          : CryptoUtils.bytesToBase64(envelope.ciphertext);

      const unsealed = await unsealMessage(
        ciphertextStr,
        recipientPrivateKeyBytes,
        this.userId,
        this.deviceId,
        sealedSenderConfig,
        envelope.serverTimestamp,
        this.logger
      );

      // Reconstruct envelope with revealed sender identity
      const innerEnvelope = reconstructEnvelope(envelope, unsealed);

      // Recursively decrypt the inner message (now a standard ciphertext)
      return this.decrypt(innerEnvelope);
    }

    // Validate message type before processing
    // Server only sends the 5 envelope types. Client-to-client types (typing_indicator,
    // delivery_receipt, sender_key_distribution) are encrypted Content inside ciphertext.
    const validMessageTypes = [
      'prekey_bundle',
      'ciphertext',
      'sender_key',
      'server_delivery_receipt',
      'unidentified_sender',
    ] as const;
    if (!validMessageTypes.includes(envelope.messageType as (typeof validMessageTypes)[number])) {
      throw new EncryptionError(
        `Unknown message type: ${envelope.messageType}`,
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType, senderId: envelope.senderUserId }
      );
    }

    const lockKey = `decrypt:${envelope.senderUserId}:${envelope.senderDeviceId}`;

    return this.lock.acquire(lockKey, async () => {
      this.logger.debug('Handling incoming envelope', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          senderId: envelope.senderUserId,
          senderDeviceId: envelope.senderDeviceId,
          messageType: envelope.messageType,
        },
      });

      let plaintext: string;
      // Set for group messages once the frame's distribution identifier has
      // been resolved against the local sender key store. The envelope carries
      // no group, so this is the only place a group becomes known on receive.
      let resolvedGroupId: string | null = null;

      // Route on the envelope type. `sender_key` says "decrypt this as a
      // framed SenderKeyMessage". It does not say which group, and cannot.
      // That is the point of not putting a group on the envelope.
      if (envelope.messageType === 'sender_key') {
        const group = await this.decryptGroup(envelope);
        plaintext = group.plaintext;
        resolvedGroupId = group.groupId;
      } else {
        // Pairwise message - use SESAME for session convergence
        const sesameMessage = this.toSesameMessage(envelope);
        plaintext = await this.decryptPairwise(sesameMessage);
      }

      // Create decrypted envelope for hook
      const receivedAt = Date.now();

      const inspectedContent = this.getResolvedContentAdapter().inspectContent(plaintext);

      // For DMs, compute canonical conversation ID: dm:${sorted(user1, user2)}
      // Groups use their group ID directly. Sent sync transcripts override this
      // with the transcript's destination conversation.
      const conversationId =
        inspectedContent?.conversationId ||
        resolvedGroupId ||
        this.getDirectConversationId(envelope.senderUserId);

      // Extract client timestamp from decrypted content
      // Text messages: dataMessage.timestamp, Attachments: timestamp at top level
      let clientTimestamp = receivedAt;
      let hasContentTimestamp = false;
      const contentTimestamp = inspectedContent?.timestamp;
      if (typeof contentTimestamp === 'number') {
        clientTimestamp = contentTimestamp;
        hasContentTimestamp = true;
      }

      // Replay attack prevention
      // Validate envelope.timestamp matches content timestamp after decryption
      if (envelope.timestamp !== undefined && hasContentTimestamp) {
        if (envelope.timestamp !== clientTimestamp) {
          throw new EncryptionError(
            `Timestamp mismatch: envelope=${envelope.timestamp}, content=${clientTimestamp}. Potential replay attack.`,
            EncryptionErrorCode.REPLAY_DETECTED
          );
        }
      }

      recordServerClockSample(envelope.serverTimestamp, receivedAt);

      const decryptedEnvelope: DecryptedEnvelope = {
        messageId: envelope.id || `${envelope.senderUserId}-${receivedAt}`,
        sessionId: ProtocolAddress.toString(
          ProtocolAddress.create(envelope.senderUserId, envelope.senderDeviceId)
        ),
        senderId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        conversationId,
        content: plaintext,
        timestamp: clientTimestamp, // Use client timestamp for receipt matching
        serverTimestamp: envelope.serverTimestamp,
        receivedAt,
        isGroup: resolvedGroupId !== null,
        messageType: envelope.messageType as DecryptedEnvelope['messageType'],
      };

      return decryptedEnvelope;
    });
  }

  /**
   * Encrypt outgoing message - routes based on recipient type
   *
   * Routes based on recipientId:
   * - Group ID (prefixed) → encryptToGroup (Sender Keys)
   * - Binary content with mimeType → encryptBlob (two-layer encryption)
   * - User ID → encryptToUser (SESAME)
   *
   * @param recipientId - User ID or group ID (groups use the package group ID prefix)
   * @param content - Uint8Array bytes to encrypt and send
   * @param options - Optional send options (mimeType for binary content, etc.)
   * @returns SendResult with messageId, timestamp, and device count
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async encrypt(
    recipientId: string,
    content: Uint8Array,
    options?: SendOptions
  ): Promise<SendResult> {
    const clientMessageId = options?.clientMessageId ?? (await CryptoUtils.generateUuidV4());
    const durableOptions = { ...options, clientMessageId };
    const lockKey = `encrypt:${recipientId}`;

    try {
      return await this.lock.acquire(lockKey, async () => {
        // 1. Route binary file data (Uint8Array with isBinary flag) to blob encryption
        if (durableOptions.isBinary) {
          return this.encryptBinaryAttachment(recipientId, content, durableOptions);
        }

        // 2. Detect recipient type (group vs user)
        if (isGroupId(recipientId)) {
          return this.encryptToGroup(recipientId, content, durableOptions);
        }

        // 3. Send to user (existing SESAME path)
        return this.encryptToUser(recipientId, content, durableOptions);
      });
    } catch (error) {
      throw attachClientMessageId(error, clientMessageId);
    }
  }

  /**
   * Encrypt and upload attachment data without sending a standalone message.
   */
  async uploadAttachment(
    data: Uint8Array,
    options: SendOptions & { mimeType: string }
  ): Promise<PreparedAttachmentUpload> {
    const lockKey = `attachment-upload:${options.mimeType}`;
    return this.lock.acquire(lockKey, async () => this.prepareAttachmentUpload(data, options));
  }

  // ============================================================================
  // PRIVATE - Decryption
  // ============================================================================

  /**
   * Convert Envelope to SesameMessage for SESAME receive path
   */
  private toSesameMessage(envelope: Envelope): SesameMessage {
    // SessionID format is "userId:deviceId" (from ProtocolAddress.toString())
    const sessionId = `${envelope.senderUserId}:${envelope.senderDeviceId}`;

    return {
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      recipientUserId: this.userId, // We are the recipient
      recipientDeviceId: this.deviceId,
      sessionId,
      // Ciphertext is base64-encoded on relay, convert back to Uint8Array
      // SESAME will deserialize it back to Ciphertext (branded base64 string) internally
      ciphertext:
        typeof envelope.ciphertext === 'string'
          ? base64ToBytes(envelope.ciphertext as Base64)
          : (envelope.ciphertext as Uint8Array),
      isInitiating: envelope.messageType === 'prekey_bundle',
      initHeader: null, // Extracted from ciphertext by SESAME
      timestamp: envelope.timestamp,
    };
  }

  /**
   * Decrypt a pairwise message via SESAME
   *
   * Public for use by SignalProtocolClient.receive() which takes raw SesameMessage.
   *
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  async decryptPairwise(sesameMessage: SesameMessage): Promise<string> {
    try {
      const plaintextBytes = await this.sesameManager.receive(sesameMessage);
      const plaintext = this.encodeLosslessPlaintext(plaintextBytes);

      this.logger.debug('Message received and decrypted', {
        category: 'E2EE',
        data: {
          senderUserId: sesameMessage.senderUserId,
          senderDeviceId: sesameMessage.senderDeviceId,
        },
      });

      return plaintext;
    } catch (error) {
      // Preserve EncryptionError for client-layer handling (e.g., PREKEY_NOT_FOUND triggers key rotation)
      if (error instanceof EncryptionError) {
        throw error;
      }
      throw new EncryptionError(
        'Failed to decrypt message',
        EncryptionErrorCode.DECRYPTION_FAILED,
        {
          originalError: error as Error,
          senderUserId: sesameMessage.senderUserId,
        }
      );
    }
  }

  /**
   * Decrypt a group message via Sender Keys.
   *
   * The envelope names no group, so the group is resolved from the opaque
   * distribution identifier inside the frame and returned alongside the
   * plaintext. Callers need it for the conversation ID and cannot read it off
   * the envelope.
   *
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  private async decryptGroup(envelope: Envelope): Promise<{
    plaintext: string;
    groupId: string;
  }> {
    // Get the framed SenderKeyMessage bytes
    let framedBytes: Uint8Array;
    if (typeof envelope.ciphertext === 'string') {
      // Base64-encoded framed SenderKeyMessage
      framedBytes = CryptoUtils.base64ToBytes(envelope.ciphertext as Base64);
    } else {
      framedBytes = envelope.ciphertext;
    }

    const groupId = await this.senderKeyManager.resolveGroupForFramedMessage(
      framedBytes,
      envelope.senderUserId,
      envelope.senderDeviceId
    );

    if (groupId === null) {
      // No stored sender key claims this distribution identifier, so there is
      // nothing to decrypt against. Same remedy as a missing key: ask the
      // sender to redistribute.
      throw new EncryptionError(
        `No sender key from ${envelope.senderUserId} matches this group message - request key distribution`,
        EncryptionErrorCode.SESSION_NOT_FOUND
      );
    }

    try {
      const plaintext = await this.senderKeyManager.decryptGroupMessage(
        groupId,
        envelope.senderUserId,
        envelope.senderDeviceId,
        framedBytes
      );

      this.logger.debug('Decrypted group message', {
        category: 'E2EE',
        data: {
          groupId,
          senderId: envelope.senderUserId,
        },
      });

      return { plaintext, groupId };
    } catch (error) {
      const err = error as Error;
      if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
        throw new EncryptionError(
          `No sender key from ${envelope.senderUserId} for group ${groupId} - request key distribution`,
          EncryptionErrorCode.SESSION_NOT_FOUND,
          { originalError: err }
        );
      }
      if (err.message?.includes('INVALID_SIGNATURE')) {
        throw new EncryptionError(
          `Invalid signature on group message from ${envelope.senderUserId}`,
          EncryptionErrorCode.DECRYPTION_FAILED,
          { originalError: err }
        );
      }
      if (err.message?.includes('MESSAGE_TOO_OLD')) {
        throw new EncryptionError(
          'Cannot decrypt old group message (forward secrecy)',
          EncryptionErrorCode.DECRYPTION_FAILED,
          { originalError: err }
        );
      }
      throw new EncryptionError(
        `Failed to decrypt group message from ${envelope.senderUserId}`,
        EncryptionErrorCode.DECRYPTION_FAILED,
        { originalError: err }
      );
    }
  }

  // ============================================================================
  // PRIVATE - Encryption
  // ============================================================================

  /**
   * Create sessions with a recipient user if none exist
   *
   * Checks if any session exists with the recipient. If not, uses the session
   * establisher callback to fetch prekey bundles and create sessions.
   *
   * @throws {EncryptionError} SESSION_NOT_FOUND if sessions cannot be established
   */
  private async ensureSessionsForUser(recipientUserId: string): Promise<void> {
    // Check if we have any session with this user via SESAME UserRecord
    const userRecord = await this.sesameManager.getUserRecord(recipientUserId);
    if (userRecord && userRecord.devices.size > 0) {
      // Check if at least one device has an active session
      const hasActiveSession = Array.from(userRecord.devices.values()).some(
        (device) => device.session?.currentSession !== null
      );
      if (hasActiveSession) {
        return; // Sessions exist, nothing to do
      }
    }

    // No sessions exist - need to establish them
    this.logger.debug('No session exists, auto-establishing', {
      category: 'E2EE',
      data: { recipientUserId, hasUserRecord: !!userRecord },
    });

    if (!this.sessionEstablisher) {
      throw new EncryptionError(
        `No session with ${recipientUserId} and auto-establishment not configured`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { recipientUserId }
      );
    }

    if (!this.relay) {
      throw new EncryptionError(
        'Cannot auto-establish session: relay server not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { recipientUserId }
      );
    }

    let result: Awaited<ReturnType<SessionEstablisher>>;
    try {
      // Use retry logic for transient network failures
      result = await withRetry(
        async () => {
          const attempt = await this.sessionEstablisher!(recipientUserId);
          if (attempt.establishedDevices.length === 0 && attempt.failedDeviceErrors.length > 0) {
            throw attempt.failedDeviceErrors[0]!.error;
          }
          return attempt;
        },
        {
          operationName: 'establishSession',
          maxRetries: 2,
          baseDelay: 500,
        }
      );
    } catch (error) {
      // Re-throw EncryptionErrors, wrap others
      if (error instanceof EncryptionError) {
        throw error;
      }

      // Check for rate limiting
      const errorMessage = (error as Error).message?.toLowerCase() || '';
      if (errorMessage.includes('rate limit')) {
        throw new EncryptionError(
          `Rate limited while establishing session with ${recipientUserId}`,
          EncryptionErrorCode.PREKEY_FETCH_RATE_LIMITED,
          { originalError: error as Error, recipientUserId }
        );
      }

      throw new EncryptionError(
        `Failed to establish session with ${recipientUserId} after retries`,
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { originalError: error as Error, recipientUserId }
      );
    }

    if (result.establishedDevices.length === 0) {
      throw new EncryptionError(
        `Recipient ${recipientUserId} has no available prekey bundles - they may not have registered encryption keys`,
        EncryptionErrorCode.RECIPIENT_NOT_REGISTERED,
        { recipientUserId, failedDevices: result.failedDevices }
      );
    }

    this.logger.info('Auto-established sessions', {
      category: 'E2EE',
      data: {
        recipientUserId,
        establishedDevices: result.establishedDevices,
        failedDevices: result.failedDevices,
      },
    });
  }

  /**
   * Encrypt to a single user (all their devices) via SESAME
   */
  private async encryptToUser(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    return this.encryptToUserWithOutbox(recipientUserId, plaintextBytes, options);
  }
  private async encryptToUserWithOutbox(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    return withOutgoingMessageIntentLock(this.storage, options.clientMessageId, () =>
      this.encryptToUserWithOutboxLocked(recipientUserId, plaintextBytes, options)
    );
  }

  private async encryptToUserWithOutboxLocked(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    const plaintextDigest = CryptoUtils.bytesToBase64(await CryptoUtils.sha256(plaintextBytes));
    const existing = await getOutgoingMessageIntent(this.storage, options.clientMessageId);

    if (existing) {
      if (
        existing.recipientId !== recipientUserId ||
        existing.plaintextDigest !== plaintextDigest ||
        (options.timestamp !== undefined && existing.clientTimestamp !== options.timestamp) ||
        existing.contentHint !== options.contentHint
      ) {
        throw new Error('A clientMessageId cannot identify two different logical sends');
      }
      if (existing.result) return existing.result;
      return this.sendStoredDirectIntent(existing, plaintextBytes);
    }

    await this.ensureSessionsForUser(recipientUserId);
    const sealedSender = this.relay ? await this.resolveSealedSenderContext(recipientUserId) : null;
    const directSealedSender =
      sealedSender && this.relay?.sendMultiRecipientUnidentified ? sealedSender : null;
    const transportMode = directSealedSender
      ? directSealedSender.config.deliveryMode === 'required'
        ? 'sealed_sender_required'
        : 'sealed_sender_preferred'
      : 'identified';
    if (directSealedSender && directSealedSender.auth.type !== 'accessKey') {
      throw new Error('Direct sealed-sender delivery requires access-key authorization');
    }
    const sealedSenderAuth =
      directSealedSender?.auth.type === 'accessKey' ? { ...directSealedSender.auth } : undefined;

    const clientTimestamp = options.timestamp ?? Date.now();
    const syncPlaintext = this.buildSentSyncTranscript(
      this.getDirectConversationId(recipientUserId),
      plaintextBytes,
      clientTimestamp,
      recipientUserId
    );
    let batch: OutgoingMessageBatch;
    try {
      batch = await this.sesameManager.send(recipientUserId, plaintextBytes, {
        clientTimestamp,
        syncPlaintext,
      });
    } catch (error) {
      if (error instanceof EncryptionError) throw error;
      throw new EncryptionError(
        'Failed to encrypt message for user',
        EncryptionErrorCode.ENCRYPTION_FAILED,
        { originalError: error as Error, recipientUserId }
      );
    }

    this.logger.debug('Message encrypted for user devices', {
      category: 'E2EE',
      data: {
        recipientUserId,
        deviceCount: batch.deviceMessages.length,
        syncCount: batch.syncMessages.length,
      },
    });

    const deviceMessages = await Promise.all(
      batch.deviceMessages.map((message) =>
        this.prepareStoredDirectDeviceMessage(message, directSealedSender)
      )
    );

    const syncMessages: StoredOutgoingDeviceMessage[] = batch.syncMessages.map((msg, index) => ({
      recipientUserId: msg.recipientUserId,
      recipientDeviceId: msg.recipientDeviceId,
      timestamp: msg.timestamp,
      clientMessageId: `${options.clientMessageId}:sync:${index}`,
      ciphertext:
        typeof msg.ciphertext === 'string'
          ? msg.ciphertext
          : CryptoUtils.bytesToBase64(msg.ciphertext),
      messageType: getEnvelopeMessageType(msg.ciphertext),
    }));

    const intent: StoredOutgoingMessageIntent = {
      kind: 'direct',
      clientMessageId: options.clientMessageId,
      recipientId: recipientUserId,
      plaintextDigest,
      clientTimestamp,
      createdAt: Date.now(),
      transportMode,
      ...(sealedSenderAuth && { sealedSenderAuth }),
      ...(options.contentHint !== undefined && {
        contentHint: options.contentHint,
      }),
      deviceMessages,
      syncMessages,
    };
    await storeOutgoingMessageIntent(this.storage, intent);
    return this.sendStoredDirectIntent(intent, plaintextBytes);
  }

  private async prepareStoredDirectDeviceMessage(
    message: import('../internal/sesame/types').SesameMessage,
    sealedSender: Exclude<
      Awaited<ReturnType<typeof SignalProtocolServiceCipher.prototype.resolveSealedSenderContext>>,
      null
    > | null
  ): Promise<StoredOutgoingDeviceMessage> {
    const messageType = getEnvelopeMessageType(message.ciphertext);
    const session =
      messageType === 'prekey_bundle'
        ? await this.sesameManager.getSession(message.recipientUserId, message.recipientDeviceId)
        : null;
    const storedMessage: StoredOutgoingDeviceMessage = {
      recipientUserId: message.recipientUserId,
      recipientDeviceId: message.recipientDeviceId,
      timestamp: message.timestamp,
      ciphertext:
        typeof message.ciphertext === 'string'
          ? message.ciphertext
          : CryptoUtils.bytesToBase64(message.ciphertext),
      messageType,
      ...(session?.currentSession?.remoteRegistrationId !== undefined && {
        recipientRegistrationId: session.currentSession.remoteRegistrationId,
      }),
    };
    if (sealedSender) {
      storedMessage.sealedSenderMessage = await this.serializeDirectSealedSenderMessage(
        storedMessage,
        storedMessage.ciphertext,
        storedMessage.messageType,
        storedMessage.recipientRegistrationId,
        sealedSender
      );
    }
    return storedMessage;
  }

  private async repairRejectedDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array
  ): Promise<StoredOutgoingDeviceMessage> {
    if (!this.staleSessionRefresher) throw new Error('Stale-session refresh is not configured');
    const refreshed = await this.staleSessionRefresher(
      rejected.recipientUserId,
      rejected.recipientDeviceId
    );
    if (!refreshed) {
      throw new EncryptionError(
        'Failed to refresh a rejected recipient device',
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { recipientUserId: rejected.recipientUserId }
      );
    }

    const freshMessage = await this.sesameManager.sendMessage(
      rejected.recipientUserId,
      rejected.recipientDeviceId,
      plaintextBytes,
      { clientTimestamp: intent.clientTimestamp, includeSyncMessages: false }
    );
    let sealedSender: Exclude<
      Awaited<ReturnType<typeof SignalProtocolServiceCipher.prototype.resolveSealedSenderContext>>,
      null
    > | null = null;
    if (intent.transportMode !== 'identified') {
      sealedSender = await this.resolveSealedSenderContext(rejected.recipientUserId);
      if (!sealedSender || sealedSender.auth.type !== 'accessKey') {
        throw new Error('Cannot rebuild a sealed-sender transmission after session refresh');
      }
    }
    const replacement = await this.prepareStoredDirectDeviceMessage(freshMessage, sealedSender);
    await replaceOutgoingDirectDeviceMessage(
      this.storage,
      intent.clientMessageId,
      rejected,
      replacement
    );
    return replacement;
  }

  private async sendStoredDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    if (
      intent.transportMode !== 'identified' &&
      (!message.sealedSenderMessage || !intent.sealedSenderAuth)
    ) {
      throw new Error('Corrupt sealed-sender outbox intent');
    }
    return intent.transportMode === 'identified'
      ? this.sendToDevice(
          message,
          message.ciphertext,
          message.messageType,
          message.recipientRegistrationId,
          null,
          intent.contentHint,
          intent.clientMessageId
        )
      : this.sendToDevice(
          message,
          message.ciphertext,
          message.messageType,
          message.recipientRegistrationId,
          null,
          intent.contentHint,
          intent.clientMessageId,
          {
            sentMessageBase64: message.sealedSenderMessage!,
            auth: intent.sealedSenderAuth!,
            deliveryMode:
              intent.transportMode === 'sealed_sender_required' ? 'required' : 'preferred',
          }
        );
  }

  private async sendStoredDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array
  ): Promise<SendResult> {
    if (intent.kind !== 'direct') throw new Error('Expected a direct outbox intent');
    if (!this.relay) {
      const result = {
        clientMessageId: intent.clientMessageId,
        messageId: `local-${intent.clientTimestamp}`,
        timestamp: intent.clientTimestamp,
        recipientDeviceCount: intent.deviceMessages.length,
      };
      await completeOutgoingMessageIntent(this.storage, intent.clientMessageId, result);
      return result;
    }

    let messageId = `local-${intent.clientTimestamp}`;
    let timestamp = intent.clientTimestamp;

    for (const msg of intent.deviceMessages) {
      let result: { messageId: string; serverTimestamp: number };
      try {
        result = await this.sendStoredDirectDeviceMessage(intent, msg);
      } catch (error) {
        if (!isConclusiveDeviceRejection(error)) throw error;
        const replacement = await this.repairRejectedDirectDeviceMessage(
          intent,
          msg,
          plaintextBytes
        );
        result = await this.sendStoredDirectDeviceMessage(intent, replacement);
      }
      if (messageId.startsWith('local-')) {
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
      }
    }

    for (const msg of intent.syncMessages) {
      await this.relay.send({
        targetUserId: msg.recipientUserId,
        targetDeviceId: msg.recipientDeviceId,
        senderUserId: this.userId,
        senderDeviceId: this.deviceId,
        ciphertext: msg.ciphertext,
        messageType: msg.messageType,
        deliveryClass: 'background-sync',
        timestamp: msg.timestamp,
        clientMessageId: msg.clientMessageId,
      });
    }

    const result = {
      clientMessageId: intent.clientMessageId,
      messageId,
      timestamp,
      recipientDeviceCount: intent.deviceMessages.length,
    };
    await completeOutgoingMessageIntent(this.storage, intent.clientMessageId, result);
    return result;
  }

  private async encryptToGroupWithOutbox(
    actualGroupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    return sendGroupWithExactOutbox(
      {
        storage: this.storage,
        ...(this.relay && { relay: this.relay }),
        senderUserId: this.userId,
        senderDeviceId: this.deviceId,
        deliveryMode: this.sealedSenderDeliveryMode,
        preparePayload: async (groupId, bytes, sendOptions) => {
          const prepared = await this.prepareGroupSenderKeyPayload(groupId, bytes, sendOptions);
          return {
            ciphertext: CryptoUtils.bytesToBase64(prepared.ciphertext),
            preMessages: prepared.preMessages,
            ...(prepared.senderKeyDistributionId && {
              senderKeyDistributionId: prepared.senderKeyDistributionId,
            }),
          };
        },
        confirmSenderKeyDistributionSent: (groupId, senderKeyId) =>
          this.senderKeyManager.confirmSenderKeyDistributionSent(
            groupId,
            this.userId,
            this.deviceId,
            senderKeyId
          ),
        resolveMemberDevices: (groupId, sendOptions) =>
          this.resolveGroupMemberDevices(groupId, sendOptions),
        prepareSharedMessage: async (groupId, members, ciphertext) => {
          if (
            members.length === 0 ||
            this.sealedSenderDeliveryMode === 'disabled' ||
            !this.sealedSenderProvider ||
            !this.endorsementManager ||
            !this.relay?.sendMultiRecipientUnidentified
          ) {
            return undefined;
          }
          const prepared = await prepareGroupSharedMessage({
            storage: this.storage,
            senderKeys: await this.sealedSenderProvider(),
            members,
            encryptedMessageBase64: ciphertext,
          });
          return prepared
            ? {
                groupId,
                sentMessageBase64: prepared.sentMessageBase64,
                recipientUserIds: prepared.recipientUserIds,
                deliveryMode:
                  this.sealedSenderDeliveryMode === 'required' ? 'required' : 'preferred',
              }
            : undefined;
        },
        prepareDeviceMessage: (member, groupId, ciphertext, timestamp) =>
          this.prepareStoredGroupDeviceMessage(member, groupId, ciphertext, timestamp),
        prepareSyncMessages: async (groupId, bytes, timestamp, clientMessageId) => {
          if (!this.relay) return [];
          const syncPayload = this.buildSentSyncTranscript(groupId, bytes, timestamp);
          const prepared = await this.sesameManager.sendToLocalOtherDevices(syncPayload, {
            clientTimestamp: timestamp,
            includeSyncMessages: false,
          });
          return prepared.map((message, index) => ({
            recipientUserId: message.recipientUserId,
            recipientDeviceId: message.recipientDeviceId,
            timestamp: message.timestamp,
            clientMessageId: `${clientMessageId}:sync:${index}`,
            ciphertext:
              typeof message.ciphertext === 'string'
                ? message.ciphertext
                : CryptoUtils.bytesToBase64(message.ciphertext),
            messageType: getEnvelopeMessageType(message.ciphertext),
          }));
        },
        resolveGroupAuthorization: (groupId, recipients) =>
          this.resolveGroupSendAuthorization(groupId, recipients),
        reportIdentifiedFallback: (recipientUserId) =>
          this.reportIdentifiedFallback(recipientUserId),
        sendPreparedSealedDevice: (intent, message, auth) =>
          this.sendToDevice(
            message,
            message.ciphertext,
            message.messageType,
            undefined,
            null,
            undefined,
            intent.clientMessageId,
            {
              sentMessageBase64: message.sealedSenderMessage!,
              auth,
              deliveryMode: message.sealedSenderDeliveryMode ?? 'preferred',
            }
          ),
      },
      actualGroupId,
      plaintextBytes,
      options
    );
  }

  private async prepareStoredGroupDeviceMessage(
    member: GroupMemberDevice,
    groupId: string,
    ciphertext: string,
    timestamp: number
  ): Promise<StoredOutgoingDeviceMessage> {
    const stored: StoredOutgoingDeviceMessage = {
      recipientUserId: member.userId,
      recipientDeviceId: member.deviceId,
      timestamp,
      ciphertext,
      messageType: 'sender_key',
    };
    const sealedSender = await this.resolveSealedSenderContext(member.userId, groupId);
    if (!sealedSender || !this.relay?.sendMultiRecipientUnidentified) return stored;

    stored.sealedSenderMessage = await this.serializeDirectSealedSenderMessage(
      stored,
      ciphertext,
      'sender_key',
      undefined,
      sealedSender
    );
    stored.sealedSenderDeliveryMode =
      sealedSender.config.deliveryMode === 'required' ? 'required' : 'preferred';
    if (sealedSender.auth.type === 'accessKey') {
      stored.sealedSenderAuthorization = 'access_key';
      stored.sealedSenderAccessKey = sealedSender.auth.unidentifiedAccessKey;
    } else {
      stored.sealedSenderAuthorization = 'group_send_token';
    }
    return stored;
  }

  private async resolveGroupSendAuthorization(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<Extract<SealedSenderAuth, { type: 'groupSendToken' }> | null> {
    if (!this.endorsementManager || recipientUserIds.length === 0) return null;
    const { needsRefresh, reason } = await this.endorsementManager.shouldRefreshEndorsements(
      groupId,
      recipientUserIds
    );
    if (needsRefresh && this.endorsementRefresher) {
      await this.endorsementRefresher(groupId, recipientUserIds);
      this.logger.debug('Refreshed endorsements before durable group send', {
        category: 'E2EE',
        data: { groupId, reason },
      });
    }
    const groupSecretParams = this.groupSecretParamsProvider
      ? await this.groupSecretParamsProvider(groupId)
      : null;
    const combined = await this.endorsementManager.getCombinedToken(
      groupId,
      recipientUserIds,
      groupSecretParams ?? undefined
    );
    return combined
      ? {
          type: 'groupSendToken',
          groupSendToken: combined.token,
          recipientAciBytes: combined.aciBytesByUserId,
        }
      : null;
  }

  private async serializeDirectSealedSenderMessage(
    msg: {
      recipientUserId: string;
      recipientDeviceId: number;
    },
    ciphertextBase64: string,
    messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key',
    recipientRegistrationId: number | undefined,
    sealedSender: ResolvedSealedSenderContext
  ): Promise<string> {
    return serializeDirectSealedSenderTransport(
      msg,
      ciphertextBase64,
      messageType,
      recipientRegistrationId,
      sealedSender
    );
  }

  /**
   * Resolve sealed sender context for a recipient.
   *
   * Authorization priority:
   * 1. GroupSend endorsement token (for group messages when endorsementManager is set)
   * 2. Per-contact mode-based UAK (existing path)
   *
   * Mode-aware selection for priority 2:
   *
   * | Mode         | Behavior                                                       |
   * |--------------|----------------------------------------------------------------|
   * | DISABLED     | Return null immediately (skip sealed sender)                   |
   * | UNRESTRICTED | Use zeroed 16-byte key (no profile key needed)                 |
   * | ENABLED      | Derive UAK from profile key; return null if no profile key     |
   * | UNKNOWN      | Use derived UAK if profile key available, else use zeroed key  |
   *
   * Returns null if sealed sender is not enabled or recipient identity is not known.
   * Pre-fetches the sender certificate and identity keys so they can be reused
   * across all device messages in a send batch.
   *
   * @param recipientUserId - User ID of the message recipient
   * @param groupId - Optional group ID. When provided, endorsement-based auth is attempted first
   *
   */
  private async resolveSealedSenderContext(
    recipientUserId: string,
    groupId?: string
  ): Promise<ResolvedSealedSenderContext | null> {
    return resolveSealedSenderSendContext(
      {
        storage: this.storage,
        deliveryMode: this.sealedSenderDeliveryMode,
        relaySupportsUnidentified: Boolean(this.relay?.sendMultiRecipientUnidentified),
        ...(this.sealedSenderProvider && {
          provider: this.sealedSenderProvider,
        }),
        ...(this.contactProfileStateStore && {
          contactProfileStateStore: this.contactProfileStateStore,
        }),
        ...(this.endorsementManager && {
          endorsementManager: this.endorsementManager,
        }),
        ...(this.groupSecretParamsProvider && {
          groupSecretParamsProvider: this.groupSecretParamsProvider,
        }),
        logger: this.logger,
        useIdentifiedDeliveryOrThrow: (userId, reason) =>
          this.useIdentifiedDeliveryOrThrow(userId, reason),
      },
      recipientUserId,
      groupId
    );
  }

  /**
   * Send a single ciphertext to a device, optionally wrapping with sealed sender.
   *
   * When sealed sender context is available:
   * 1. Wraps the ciphertext with the multi-recipient format for one recipient
   * 2. Uses relay.sendMultiRecipientUnidentified() for anonymous delivery
   *
   * On sealed sender auth failure, transitions the recipient's
   * UnidentifiedAccessMode before falling back to identified delivery:
   *
   * | Current Mode   | -> New Mode | Rationale                        |
   * |----------------|-------------|----------------------------------|
   * | UNRESTRICTED   | UNKNOWN     | Might have wrong info, re-verify |
   * | ENABLED        | DISABLED    | Key definitely wrong             |
   * | UNKNOWN        | DISABLED    | Confirmed doesn't work           |
   *
   */
  private async sendToDevice(
    msg: {
      recipientUserId: string;
      recipientDeviceId: number;
      timestamp: number;
      clientMessageId?: string;
    },
    ciphertextBase64: string,
    messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key',
    recipientRegistrationId: number | undefined,
    sealedSender: Awaited<
      ReturnType<typeof SignalProtocolServiceCipher.prototype.resolveSealedSenderContext>
    >,
    contentHint?: ContentHint,
    clientMessageId?: string,
    preparedSealedSender?: {
      sentMessageBase64: string;
      auth: SealedSenderAuth;
      deliveryMode: 'preferred' | 'required';
    }
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    const effectiveClientMessageId = msg.clientMessageId ?? clientMessageId;

    if (preparedSealedSender && !this.relay!.sendMultiRecipientUnidentified) {
      if (preparedSealedSender.deliveryMode === 'required') {
        throw new EncryptionError(
          'Required sealed-sender relay capability is unavailable',
          EncryptionErrorCode.SEALED_SENDER_REQUIRED,
          { recipientUserId: msg.recipientUserId }
        );
      }
    }

    // Sealed sender path: use the V2 upload format for one recipient. V2 has
    // no two-recipient minimum; its recipient-count field permits this exact
    // direct-delivery shape.
    if ((sealedSender || preparedSealedSender) && this.relay!.sendMultiRecipientUnidentified) {
      const prepared =
        preparedSealedSender ??
        (sealedSender
          ? {
              sentMessageBase64: await this.serializeDirectSealedSenderMessage(
                msg,
                ciphertextBase64,
                messageType,
                recipientRegistrationId,
                sealedSender
              ),
              auth: sealedSender.auth,
              deliveryMode:
                sealedSender.config.deliveryMode === 'required' ? 'required' : 'preferred',
            }
          : undefined);
      if (!prepared) throw new Error('Missing sealed-sender delivery state');

      try {
        const result = await this.relay!.sendMultiRecipientUnidentified!(
          prepared.sentMessageBase64,
          prepared.auth,
          msg.timestamp,
          'user-visible',
          [msg.recipientUserId],
          effectiveClientMessageId
        );
        if (result.uuids404.length > 0) {
          throw new SealedSenderRecipientRejectedError();
        }
        return result;
      } catch (error) {
        // Fall back to identified delivery only for sealed-sender authorization
        // failures. Other failures retain their original error semantics.
        if (error instanceof SealedSenderAuthError) {
          if (prepared.deliveryMode === 'required') {
            throw error;
          }
          // Restrict the cached mode after authorization fails.
          try {
            if (this.contactProfileStateStore) {
              const currentMode = await this.contactProfileStateStore.getUnidentifiedAccessMode(
                msg.recipientUserId
              );
              let newMode: UnidentifiedAccessModeType;
              switch (currentMode) {
                case UnidentifiedAccessMode.UNRESTRICTED:
                  newMode = UnidentifiedAccessMode.UNKNOWN;
                  break;
                case UnidentifiedAccessMode.ENABLED:
                case UnidentifiedAccessMode.UNKNOWN:
                default:
                  newMode = UnidentifiedAccessMode.DISABLED;
                  break;
              }
              await this.contactProfileStateStore.updateUnidentifiedAccessMode(
                msg.recipientUserId,
                newMode
              );

              this.logger.info(
                'Sealed sender auth failed, transitioned mode and falling back to identified delivery',
                {
                  category: 'E2EE',
                  data: {
                    recipientUserId: msg.recipientUserId,
                    previousMode: currentMode,
                    newMode,
                  },
                }
              );
            } else {
              this.logger.debug(
                'No contact profile state store configured after sealed sender failure',
                {
                  category: 'E2EE',
                  data: { recipientUserId: msg.recipientUserId },
                }
              );
            }
          } catch (modeError) {
            // Non-fatal: mode transition failure should not block message delivery
            this.logger.warn('Failed to update unidentified access mode after auth failure', {
              category: 'E2EE',
              data: {
                recipientUserId: msg.recipientUserId,
                error: (modeError as Error).message,
              },
            });
          }
          await this.reportIdentifiedFallback(msg.recipientUserId);
          // Fall through to identified path below
        } else {
          throw error;
        }
      }
    }

    // Identified sender path: standard relay send
    return this.relay!.send({
      targetUserId: msg.recipientUserId,
      targetDeviceId: msg.recipientDeviceId,
      senderUserId: this.userId,
      senderDeviceId: this.deviceId,
      ciphertext: ciphertextBase64,
      messageType,
      deliveryClass: 'user-visible',
      timestamp: msg.timestamp,
      clientMessageId: effectiveClientMessageId,
      recipientRegistrationId,
      contentHint,
    });
  }

  /**
   * Resolve the group roster to concrete devices via the relay.
   *
   * `options.groupMemberUserIds` is required for relayed group sends. Group
   * membership is local-first: each client derives it from its own decrypted
   * group state, and the relay deliberately keeps no server-side membership
   * map. A groupId → member lookup would hand the relay the social graph
   * the zero-knowledge group design exists to hide.
   */
  private async resolveGroupMemberDevices(
    groupId: string,
    options?: SendOptions
  ): Promise<GroupMemberDevice[]> {
    if (!options?.groupMemberUserIds?.length) {
      throw new EncryptionError(
        `Group send for ${groupId} requires options.groupMemberUserIds. ` +
          'The relay keeps no server-side membership map; resolve the roster ' +
          'from local group state and pass the member user IDs.',
        EncryptionErrorCode.ENCRYPTION_FAILED,
        { groupId }
      );
    }
    const deviceResults = await Promise.all(
      options.groupMemberUserIds.map((userId) => this.relay!.getActiveDevices(userId))
    );
    return deviceResults.flat();
  }

  private async prepareGroupSenderKeyPayload(
    actualGroupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number }
  ): Promise<{
    ciphertext: Uint8Array;
    preMessages: StoredOutgoingDeviceMessage[];
    senderKeyDistributionId?: string;
  }> {
    const existingKey = await this.storage.getSenderKey(actualGroupId, this.userId, this.deviceId);
    if (!existingKey) {
      throw new EncryptionError(
        `No sender key for group ${actualGroupId}. Call createGroupSenderKey() first to create and distribute the key.`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        {
          groupId: actualGroupId,
          userId: this.userId,
          deviceId: this.deviceId,
        }
      );
    }

    let distributionMessage = await this.senderKeyManager.getPendingSenderKeyDistribution(
      actualGroupId,
      this.userId,
      this.deviceId
    );
    if (!distributionMessage) {
      try {
        return {
          ciphertext: await this.senderKeyManager.encryptGroupMessage(
            actualGroupId,
            this.userId,
            this.deviceId,
            plaintextBytes
          ),
          preMessages: [],
        };
      } catch (error) {
        if (
          !(error instanceof EncryptionError) ||
          error.code !== EncryptionErrorCode.SENDER_KEY_EXPIRED
        ) {
          throw error;
        }

        this.logger.info('Sender key expired, auto-rotating', {
          category: 'E2EE',
          data: { groupId: actualGroupId },
        });
        ({ distributionMessage } = await this.senderKeyManager.rotateSenderKey(
          actualGroupId,
          this.userId,
          this.deviceId,
          { distributionPending: true }
        ));
      }
    }

    const preMessages: StoredOutgoingDeviceMessage[] = [];
    if (this.relay) {
      const members = await this.resolveGroupMemberDevices(actualGroupId, options);
      const otherMembers = members.filter((member) => member.userId !== this.userId);
      const recipientUserIds = [...new Set(otherMembers.map((member) => member.userId))];
      for (const recipientUserId of recipientUserIds) {
        await this.ensureSessionsForUser(recipientUserId);
        const skdmBytes = this.contentAdapter
          ? this.contentAdapter.serializeSenderKeyDistributionBytes(
              actualGroupId,
              distributionMessage
            )
          : new TextEncoder().encode(
              JSON.stringify({
                senderKeyDistributionMessage: JSON.stringify({
                  groupId: actualGroupId,
                  ...distributionMessage,
                }),
              })
            );
        const batch = await this.sesameManager.send(recipientUserId, skdmBytes, {
          clientTimestamp: options.timestamp,
          includeSyncMessages: false,
        });
        for (const message of batch.deviceMessages) {
          const stored = await this.prepareStoredDirectDeviceMessage(message, null);
          stored.clientMessageId = `${options.clientMessageId}:sender-key-distribution:${preMessages.length}`;
          preMessages.push(stored);
        }
      }
    }

    return {
      ciphertext: await this.senderKeyManager.encryptGroupMessage(
        actualGroupId,
        this.userId,
        this.deviceId,
        plaintextBytes
      ),
      preMessages,
      senderKeyDistributionId: distributionMessage.senderKeyId,
    };
  }

  /**
   * Encrypt to a group via Sender Keys (O(1) encryption)
   *
   * Uses the multi-recipient sealed-sender transport when anonymous delivery
   * is available, with exact per-device identified delivery otherwise.
   */
  private async encryptToGroup(
    groupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    const actualGroupId = extractGroupId(groupId);
    await this.groupSendBarrierChecker?.(actualGroupId);
    return this.encryptToGroupWithOutbox(actualGroupId, plaintextBytes, options);
  }
  /**
   * Encrypt binary attachment with two-layer encryption
   *
   * Layer 1: AES-GCM-HKDF Streaming encrypts the file (Tink format)
   * Layer 2: Signal Protocol encrypts the AES key + metadata
   *
   * Uses streaming AEAD for:
   * - Per-chunk integrity verification
   * - Streaming decryption (video playback while downloading)
   * - Truncation detection via last-segment flag
   *
   * @param recipientId - User or group ID to send to
   * @param data - Binary file data as Uint8Array (use expo-file-system File.bytes())
   * @param options - Send options including mimeType, blurHash, dimensions
   *
   * @see https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming
   */
  private async encryptBinaryAttachment(
    recipientId: string,
    data: Uint8Array,
    options: SendOptions & { clientMessageId: string }
  ): Promise<SendResult> {
    if (!this.relay) {
      throw new EncryptionError(
        'Relay server not configured. Cannot send attachments without server connection.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    const uploaded = await this.prepareAttachmentUpload(data, options);

    const attachmentPayload = serializeMediaAttachmentMessage({
      attachment: uploaded,
      timestamp: options.timestamp ?? Date.now(),
    });
    const attachmentBytes = new TextEncoder().encode(attachmentPayload);
    let result: SendResult;
    if (isGroupId(recipientId)) {
      result = await this.encryptToGroup(recipientId, attachmentBytes, options);
    } else {
      result = await this.encryptToUser(recipientId, attachmentBytes, options);
    }

    return {
      ...result,
      storageId: uploaded.storageId,
      aesKey: uploaded.key,
      segmentSize: uploaded.segmentSize,
      digest: uploaded.digest,
      contentType: uploaded.contentType,
    };
  }

  private async prepareAttachmentUpload(
    data: Uint8Array,
    options?: SendOptions
  ): Promise<PreparedAttachmentUpload> {
    if (!this.remoteObjectStore) {
      throw new EncryptionError(
        'Remote object storage not configured. Provide remoteObjectStore in SignalProtocolClient.create() config.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    return prepareMediaAttachmentUpload(data, {
      remoteObjectStore: this.remoteObjectStore,
      transfer: options?.attachment?.transfer,
      retry: options?.attachment?.retry,
      policy: options?.attachment?.policy,
      signal: options?.attachment?.signal,
      onProgress: options?.attachment?.onProgress,
      onCheckpoint: options?.attachment?.onCheckpoint,
      resume: options?.attachment?.resume,
      contentType: options?.mimeType || 'application/octet-stream',
      blurHash: options?.blurHash,
      thumbnail: options?.thumbnail,
      width: options?.width,
      height: options?.height,
      durationMs: options?.durationMs,
      waveform: options?.waveform,
      fileName: options?.fileName,
      caption: options?.caption,
      isViewOnce: options?.isViewOnce,
      flags: options?.flags,
      clientUuid: options?.clientUuid,
      cdnNumber: options?.cdnNumber,
    });
  }
}
