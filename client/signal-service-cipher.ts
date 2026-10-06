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

import { utf8Decode } from '../internal/platform';
import AsyncLock from 'async-lock';
import type {
  SignalProtocolRelayServer,
  Envelope,
  StaleSessionErrorData,
  SealedSenderAuth,
  GroupMemberDevice,
} from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { SignalProtocolLocalStore, Base64, ReceivedContent } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import { base64ToBytes } from '../internal/crypto';
import type { DecryptedEnvelope } from './event-hooks';
import { recordServerClockSample } from '../server-clock';
import { ProtocolAddress } from '../types/address';
import type { SesameManager, SesameMessage, OutgoingMessageBatch } from '../internal/sesame/types';
import { defaultSignalProtocolLogger, type Logger } from '../logger';
import { SenderKeyManager } from '../internal/protocol/sender-keys';
import { isGroupId, extractGroupId } from '../internal/groups';
import type { EndorsementManager } from './endorsement-manager';
import type { GroupReceiveAuthorizer } from './group-receive-authorization';
import { GroupSenderKeyOperations } from './group-sender-key-operations';
import type { PreparedAttachmentUpload, SendOptions, SendResult } from './types';
import { ContentHint } from '../types/messages';

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
  reconcileOutgoingDirectDeviceMessages,
  replaceOutgoingDirectDeviceMessage,
  storeOutgoingMessageIntent,
  withOutgoingMessageIntentLock,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import { FanOutError, firstItemError, type BoundedFanOut } from '../utils/bounded-fan-out';
import { withRetry } from '../utils/retry';
import {
  acquireUntilStopped,
  createRelayFanOut,
  RelayWorkStopped,
  relaySendsSealedUnderItsBound,
  rethrowRelayWorkStopped,
} from './relay-work';
import { refusesRemovedDevices, relayDeviceRefusal } from './relay-device-refusal';
import { prepareGroupSharedMessage } from './group-sealed-sender';
import { sendGroupWithExactOutbox } from './group-outbox';
import {
  reconstructEnvelope,
  resolveSealedSenderContext as resolveSealedSenderSendContext,
  serializeDirectSealedSenderMessage as serializeDirectSealedSenderTransport,
  unsealMessage,
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
 * How long a recipient's relay device list stays current before a send reads
 * it again. A device linked or removed inside this window is found by the
 * first send after it ends.
 */
export const RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS = 60_000;

/**
 * How old a recipient's device list can be for a direct send to post before
 * it reads the list again. Only a relay that refuses a removed device's
 * mailbox allows it, so the age bounds how long the client posts first on a
 * list that no read confirmed, not how long a removed device receives.
 */
const RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS = 300_000;

/** How one device post of a send runs. */
interface DevicePostControl {
  /** The stop signal of the send. No post starts after it aborts. */
  readonly stopSignal?: AbortSignal;
  /** Runs just before the relay request, and refuses the post by throwing. */
  readonly admit?: () => void;
}

/** A send-first post that waits for the reconcile pass. */
class DeferredPost extends Error {
  constructor() {
    super('The post waits for the device-list read');
    this.name = 'DeferredPost';
  }
}

/** The posts of a send-first pass, by recipient device. */
interface DirectIntentPosts {
  readonly accepted: Map<number, { messageId: string; serverTimestamp: number }>;
  readonly refused: Map<number, { error: unknown }>;
}

/** The result of a successful device-list read. */
interface RecipientDeviceList {
  readonly listed: ReadonlySet<number>;
  readonly established: readonly number[];
}

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
 * @internal Used by DefaultSignalProtocolClient.processIncomingEnvelopes and background sync
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
  const text = typeof ciphertext === 'string' ? ciphertext : utf8Decode(ciphertext);

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
  return (
    isStaleSessionError(error) ||
    error instanceof SealedSenderRecipientRejectedError ||
    relayDeviceRefusal(error)?.code === 'STALE_DEVICE'
  );
}

/** True when the relay refused this post because of the device that it names. */
function isRefusalOfDevice(error: unknown, message: StoredOutgoingDeviceMessage): boolean {
  const refusal = relayDeviceRefusal(error);
  return (
    refusal?.userId === message.recipientUserId && refusal.deviceId === message.recipientDeviceId
  );
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
 * Callback for reconciling a recipient's sessions with the relay's device list
 * Allows SignalProtocolClient to inject its session establishment logic. When
 * the send already read the recipient's devices, it passes them, and the
 * callback does not read the list again.
 */
export type SessionEstablisher = (
  recipientUserId: string,
  listedDevices?: readonly GroupMemberDevice[]
) => Promise<{
  /** Device IDs the relay lists as receiving for the recipient */
  activeDevices: number[];
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
 * The session callbacks of a send. The client binds them to the hooks of the
 * work that sends, so a resend in relay work calls the app through that work.
 */
export interface SendSessionCallbacks {
  establishSessions: SessionEstablisher;
  refreshStaleSession: StaleSessionRefresher;
}

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
  private readonly groupSenderKeys: GroupSenderKeyOperations;
  private sessionCallbacks?: SendSessionCallbacks;
  private readonly recipientDeviceListCheckedAt = new Map<string, number>();
  private sealedSenderProvider?: SealedSenderProvider;
  private sealedSenderDeliveryMode: import('./config').SealedSenderDeliveryMode = 'preferred';
  private sealedSenderIdentifiedFallback?: import('./config').SealedSenderConfig['onIdentifiedFallback'];
  private contactProfileStateStore?: ContactProfileStateStore;
  private endorsementManager?: EndorsementManager;
  private endorsementManagerResolver?: () => Promise<EndorsementManager | undefined>;
  private endorsementRefresher?: EndorsementRefresher;
  private groupSendBarrierChecker?: GroupSendBarrierChecker;
  private groupReceiveAuthorizer?: GroupReceiveAuthorizer;
  private groupSecretParamsProvider?: (
    groupId: string
  ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>;

  constructor(
    private readonly userId: string,
    private readonly deviceId: number,
    private readonly sesameManager: SesameManager,
    private readonly senderKeyManager: SenderKeyManager,
    private readonly storage: SignalProtocolLocalStore,
    private readonly relay?: SignalProtocolRelayServer,
    private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore,
    private readonly contentAdapter?: SignalProtocolContentAdapter,
    private readonly logger: Required<Logger> = defaultSignalProtocolLogger,
    private readonly fanOut: BoundedFanOut = createRelayFanOut()
  ) {
    this.groupSenderKeys = new GroupSenderKeyOperations(storage, userId, deviceId);
  }

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
    const text = utf8Decode(plaintextBytes);
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
    const relay = this.relay;
    if (!relay || syncMessages.length === 0) {
      return;
    }

    await this.sendPhase(
      syncMessages,
      (syncMsg) =>
        this.fanOut.request(() =>
          relay.send({
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
          })
        ),
      'sync'
    );
  }

  /**
   * Run one relay phase of a send: a task for each device message, at the same
   * time, under the client's relay request bound. Every device is attempted.
   * When devices fail, the phase rejects after every device settles, with the
   * error of the first failed device in input order, so a caller sees the
   * error type that a send in device order threw. Each other failure is logged.
   */
  private async sendPhase<T extends { recipientUserId: string; recipientDeviceId: number }, R>(
    messages: readonly T[],
    task: (message: T) => Promise<R>,
    phase: 'pre-message' | 'device' | 'sync',
    stopSignal?: AbortSignal
  ): Promise<R[]> {
    try {
      return await this.fanOut.all(messages, task, stopSignal);
    } catch (error) {
      if (!(error instanceof FanOutError)) throw error;
      const failed = error.outcomes.flatMap((outcome, index) =>
        outcome.ok ? [] : [{ message: messages[index]!, error: outcome.error }]
      );
      for (const { message, error: other } of failed.slice(1)) {
        this.logger.warn('A device post of a send failed', {
          category: 'E2EE',
          error: other as Error,
          data: {
            phase,
            recipientUserId: message.recipientUserId,
            deviceId: message.recipientDeviceId,
            failedDevices: failed.length,
          },
        });
      }
      throw failed[0]!.error;
    }
  }

  /**
   * Send one relay request of a device post under a slot of the client's
   * bound. An adapter that bounds its own sealed-sender posts takes a slot of
   * the same bound, so its sealed post runs without one here.
   */
  private postToRelay<T>(
    send: () => Promise<T>,
    sealed: boolean,
    control: DevicePostControl
  ): Promise<T> {
    const post = () => {
      control.admit?.();
      return send();
    };
    if (sealed && relaySendsSealedUnderItsBound(this.relay!)) {
      if (control.stopSignal?.aborted) return Promise.reject(new RelayWorkStopped());
      return new Promise<T>((resolve) => resolve(post()));
    }
    return this.fanOut.request(post, control.stopSignal);
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
   * Set the session callbacks of a send that passes none
   * Called by SignalProtocolClient after construction to inject session establishment logic
   *
   * The stale-session refresher runs when the server returns STALE_DEVICE
   * errors (device reinstalled).
   */
  setSessionCallbacks(callbacks: SendSessionCallbacks): void {
    this.sessionCallbacks = callbacks;
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
  setEndorsementManager(manager: EndorsementManager, resolve?: () => Promise<EndorsementManager | undefined>): void {
    this.endorsementManager = manager;
    this.endorsementManagerResolver = resolve;
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

  /** Bind received group content to verified local membership. */
  setGroupReceiveAuthorizer(authorize: GroupReceiveAuthorizer): void {
    this.groupReceiveAuthorizer = authorize;
  }

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
    sealedSenderConfig?: import('./config').SealedSenderConfig,
    receiveId?: string,
    stopSignal?: AbortSignal
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
      const decrypted = await this.decrypt(innerEnvelope, undefined, receiveId, stopSignal);
      return { ...decrypted, arrivedSealed: true };
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

    return acquireUntilStopped(this.lock, lockKey, async () => {
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
      const received = receiveId ? await this.storage.getReceivedContent(receiveId) : null;

      // Route on the envelope type. `sender_key` says "decrypt this as a
      // framed SenderKeyMessage". It does not say which group, and cannot.
      // That is the point of not putting a group on the envelope.
      if (envelope.messageType === 'sender_key') {
        const group = await this.decryptGroup(envelope, receiveId, received ?? undefined, stopSignal);
        plaintext = group.plaintext;
        resolvedGroupId = group.groupId;
      } else {
        // Pairwise message - use SESAME for session convergence
        const sesameMessage = this.toSesameMessage(envelope);
        plaintext = received?.plaintext ?? (await this.decryptPairwise(sesameMessage, receiveId));
      }

      // Create decrypted envelope for hook
      const receivedAt = received?.receivedAt ?? Date.now();

      const inspectedContent = this.getResolvedContentAdapter().inspectContent(plaintext);
      const distribution = inspectedContent.senderKeyDistribution;
      if (distribution) {
        if (resolvedGroupId !== null) {
          throw new EncryptionError(
            'Sender-key distributions require pairwise encryption',
            EncryptionErrorCode.INVALID_CIPHERTEXT
          );
        }
        if (!this.groupReceiveAuthorizer) {
          throw new Error('Configure verified group membership before receiving sender keys');
        }
        await this.groupSenderKeys.run(distribution.groupId, async (rawGroupId) => {
          await this.groupReceiveAuthorizer!(rawGroupId, envelope.senderUserId, 'distribution');
          await this.senderKeyManager.processSenderKeyDistribution(
            rawGroupId,
            envelope.senderUserId,
            envelope.senderDeviceId,
            distribution.distribution
          );
        }, stopSignal);
      }

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
        arrivedSealed: false,
        messageType: envelope.messageType as DecryptedEnvelope['messageType'],
      };

      return decryptedEnvelope;
    }, stopSignal);
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
   * @param sessions - Session callbacks of this send. Default: the callbacks
   *   that setSessionCallbacks set
   * @param stopSignal - The stop signal of the relay work that sends. When it
   *   aborts while the send waits for the recipient's lock, the send throws
   *   RelayWorkStopped. Default: none, and the send waits
   * @returns SendResult with messageId, timestamp, and device count
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async encrypt(
    recipientId: string,
    content: Uint8Array,
    options?: SendOptions,
    sessions = this.sessionCallbacks,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    const clientMessageId = options?.clientMessageId ?? (await CryptoUtils.generateUuidV4());
    const durableOptions = { ...options, clientMessageId };
    const encrypt = async () => {
      if (durableOptions.isBinary) {
        return this.encryptBinaryAttachment(
          recipientId,
          content,
          durableOptions,
          sessions,
          stopSignal
        );
      }
      if (isGroupId(recipientId)) {
        return this.encryptToGroup(recipientId, content, durableOptions, sessions, stopSignal);
      }
      return this.encryptToUser(recipientId, content, durableOptions, sessions, stopSignal);
    };

    try {
      // This lock keeps the sends to one recipient in order, also across an
      // attachment upload. A group send takes the group's Sender Key lock
      // only in encryptToGroup, so a receive does not wait for an upload.
      const orderKey = isGroupId(recipientId) ? extractGroupId(recipientId) : recipientId;
      return await acquireUntilStopped(this.lock, `encrypt:${orderKey}`, encrypt, stopSignal);
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
   * Public for use by DefaultSignalProtocolClient.receive() which takes raw SesameMessage.
   *
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  async decryptPairwise(sesameMessage: SesameMessage, receiveId?: string): Promise<string> {
    try {
      const plaintextBytes = await this.sesameManager.receive(sesameMessage, receiveId);
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
  private async decryptGroup(
    envelope: Envelope,
    receiveId?: string,
    received?: ReceivedContent,
    stopSignal?: AbortSignal
  ): Promise<{
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

    const groupId =
      received?.groupId ??
      (await this.senderKeyManager.resolveGroupForFramedMessage(
        framedBytes,
        envelope.senderUserId,
        envelope.senderDeviceId
      ));

    if (groupId === null) {
      // No stored sender key claims this distribution identifier, so there is
      // nothing to decrypt against. Same remedy as a missing key: ask the
      // sender to redistribute.
      throw new EncryptionError(
        `No sender key from ${envelope.senderUserId} matches this group message - request key distribution`,
        EncryptionErrorCode.SESSION_NOT_FOUND
      );
    }

    return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      await this.groupReceiveAuthorizer?.(rawGroupId, envelope.senderUserId, 'message');
      if (received) return { plaintext: received.plaintext, groupId: rawGroupId };
      try {
        const plaintext = await this.senderKeyManager.decryptGroupMessage(
          rawGroupId,
          envelope.senderUserId,
          envelope.senderDeviceId,
          framedBytes,
          receiveId
        );

        this.logger.debug('Decrypted group message', {
          category: 'E2EE',
          data: {
            groupId: rawGroupId,
            senderId: envelope.senderUserId,
          },
        });

        return { plaintext, groupId: rawGroupId };
      } catch (error) {
        const err = error as Error;
        if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
          throw new EncryptionError(
            `No sender key from ${envelope.senderUserId} for group ${rawGroupId} - request key distribution`,
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
    }, stopSignal);
  }

  // ============================================================================
  // PRIVATE - Encryption
  // ============================================================================

  /**
   * Reconcile a recipient's sessions with the relay's device list
   *
   * A send must reach every device the relay lists for the recipient, and no
   * device the relay no longer lists. The session establisher reads that list
   * again when the last read is older than
   * RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS, creates a session for each listed
   * device that has none, and this method removes each local device that is not
   * listed. Inside the window, a recipient with an active session is sent to
   * without a relay read. The relay gives no device-set version, so the window
   * is the only bound on how long a linked or removed device goes unseen.
   *
   * A direct send may post before the read when the relay refuses every post
   * to a removed device's mailbox, this client read the list in this process,
   * and that read is younger than
   * RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS. This method then returns
   * true without a read, and the send reads the list while it posts and
   * reconciles after the read. Other relays, and a list that this process did
   * not read or that is too old, await the read. A list time later than the
   * clock is too old.
   *
   * @param sendFirst - The caller can post before the read and reconcile after it
   * @param readDevices - The recipient's devices that this send read. When
   *   they are given, a reconcile uses them and does not read the list again
   * @returns True when the caller must read the list after it posts
   * @throws {EncryptionError} SESSION_NOT_FOUND if sessions cannot be established
   */
  private async ensureSessionsForUser(
    recipientUserId: string,
    sessions: SendSessionCallbacks | undefined,
    sendFirst = false,
    readDevices?: readonly GroupMemberDevice[]
  ): Promise<boolean> {
    const hasActiveSession = await this.hasActiveSession(recipientUserId);
    const listAge = this.recipientDeviceListAge(recipientUserId);
    if (hasActiveSession && listAge < RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS) {
      return false;
    }

    this.logger.debug('Reconciling recipient devices with the relay', {
      category: 'E2EE',
      data: { recipientUserId, hasActiveSession },
    });

    if (!sessions) {
      if (hasActiveSession) return false;
      throw new EncryptionError(
        `No session with ${recipientUserId} and auto-establishment not configured`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { recipientUserId }
      );
    }

    if (!this.relay) {
      if (hasActiveSession) return false;
      throw new EncryptionError(
        'Cannot auto-establish session: relay server not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { recipientUserId }
      );
    }

    if (
      sendFirst &&
      hasActiveSession &&
      listAge < RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS &&
      refusesRemovedDevices(this.relay)
    ) {
      return true;
    }

    await this.readRecipientDeviceList(
      recipientUserId,
      sessions,
      hasActiveSession,
      undefined,
      readDevices
    );
    return false;
  }

  private async hasActiveSession(recipientUserId: string): Promise<boolean> {
    const userRecord = await this.sesameManager.getUserRecord(recipientUserId);
    return (
      !!userRecord &&
      Array.from(userRecord.devices.values()).some(
        (device) => device.session?.currentSession != null
      )
    );
  }

  /** The age of this process's last successful read. A read in the future has no age. */
  private recipientDeviceListAge(recipientUserId: string): number {
    const checkedAt = this.recipientDeviceListCheckedAt.get(recipientUserId);
    const age = checkedAt === undefined ? Number.POSITIVE_INFINITY : Date.now() - checkedAt;
    return age >= 0 ? age : Number.POSITIVE_INFINITY;
  }

  /**
   * Read the recipient's device list, create the missing sessions, and remove
   * each local device that the list does not show.
   *
   * @param onList - Called with the listed devices as soon as the list arrives,
   *   before the unlisted records are removed
   * @param readDevices - The devices that this send read. When they are
   *   given, the list is not read again
   * @returns The listed and established devices, or undefined when the read
   *   failed and the known devices still receive
   */
  private async readRecipientDeviceList(
    recipientUserId: string,
    sessions: SendSessionCallbacks,
    hasActiveSession: boolean,
    onList?: (listed: ReadonlySet<number>) => void,
    readDevices?: readonly GroupMemberDevice[]
  ): Promise<RecipientDeviceList | undefined> {
    let result: Awaited<ReturnType<SessionEstablisher>>;
    try {
      // Use retry logic for transient network failures
      result = await withRetry(
        async () => {
          const attempt = await sessions.establishSessions(recipientUserId, readDevices);
          if (attempt.establishedDevices.length === 0 && attempt.failedDeviceErrors.length > 0) {
            throw attempt.failedDeviceErrors[0]!.error;
          }
          return attempt;
        },
        {
          operationName: 'establishSession',
          maxRetries: 2,
          baseDelay: 500,
          shouldRetry: (error) => !(error instanceof RelayWorkStopped),
        }
      );
    } catch (error) {
      rethrowRelayWorkStopped(error);
      if (hasActiveSession) {
        // The known devices still receive; the next send reads the list again.
        this.logger.warn('Recipient device list refresh failed, sending to known devices', {
          category: 'E2EE',
          error: error as Error,
          data: { recipientUserId },
        });
        return undefined;
      }

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

    const listedDevices = new Set(result.activeDevices);
    onList?.(listedDevices);
    const removedDevices: number[] = [];
    const reconciledRecord = await this.sesameManager.getUserRecord(recipientUserId);
    for (const deviceId of Array.from(reconciledRecord?.devices.keys() ?? [])) {
      if (listedDevices.has(deviceId)) continue;
      await this.sesameManager.removeDevice(recipientUserId, deviceId);
      removedDevices.push(deviceId);
    }

    if (result.establishedDevices.length === 0) {
      throw new EncryptionError(
        `Recipient ${recipientUserId} has no available prekey bundles - they may not have registered encryption keys`,
        EncryptionErrorCode.RECIPIENT_NOT_REGISTERED,
        { recipientUserId, failedDevices: result.failedDevices }
      );
    }

    // A device that failed stays unreached until the window ends, which keeps
    // a recipient with a broken device from costing a relay read on every send.
    this.recipientDeviceListCheckedAt.set(recipientUserId, Date.now());

    this.logger.info('Reconciled recipient devices', {
      category: 'E2EE',
      data: {
        recipientUserId,
        establishedDevices: result.establishedDevices,
        failedDevices: result.failedDevices,
        removedDevices,
      },
    });
    return { listed: listedDevices, established: result.establishedDevices };
  }

  /**
   * Encrypt to a single user (all their devices) via SESAME
   */
  private async encryptToUser(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    return this.encryptToUserWithOutbox(
      recipientUserId,
      plaintextBytes,
      options,
      sessions,
      stopSignal
    );
  }
  private async encryptToUserWithOutbox(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    return withOutgoingMessageIntentLock(this.storage, options.clientMessageId, () =>
      this.encryptToUserWithOutboxLocked(
        recipientUserId,
        plaintextBytes,
        options,
        sessions,
        stopSignal
      )
    );
  }

  private async encryptToUserWithOutboxLocked(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
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
      return this.sendStoredDirectIntent(
        await this.reconcilePendingDirectIntent(existing, plaintextBytes, sessions),
        plaintextBytes,
        sessions,
        stopSignal
      );
    }

    const sendFirst = await this.ensureSessionsForUser(recipientUserId, sessions, true);
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

    // Local work: a stop does not end it, so the intent keeps the ciphertext.
    const deviceMessages = await this.fanOut
      .all(batch.deviceMessages, (message) =>
        this.prepareStoredDirectDeviceMessage(message, directSealedSender)
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });

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
      ...(sendFirst && { reconcilePending: true as const }),
      deviceMessages,
      syncMessages,
    };
    await storeOutgoingMessageIntent(this.storage, intent);
    if (sendFirst && sessions) {
      return this.sendDirectIntentBeforeDeviceListRead(
        intent,
        plaintextBytes,
        sessions,
        stopSignal
      );
    }
    return this.sendStoredDirectIntent(intent, plaintextBytes, sessions, stopSignal);
  }

  /**
   * Post a direct intent to its known devices while the recipient's device
   * list is read, then reconcile the intent with the list and post the rest.
   *
   * The known devices are posted at the same time. A post that the relay
   * refuses because of its device waits for the read, and the read decides it:
   * an unlisted device leaves the intent without a repair, a listed device
   * with STALE_DEVICE is repaired, and a listed device with NOT_FOUND fails
   * the send. A post that has not started when the list arrives waits for the
   * reconcile pass, which starts after the read removes the unlisted device
   * records, so no message goes to a device after the read that shows its
   * removal.
   */
  private async sendDirectIntentBeforeDeviceListRead(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const arrived: { listed?: ReadonlySet<number> } = {};
    const read = this.readRecipientDeviceList(intent.recipientId, sessions, true, (listed) => {
      arrived.listed = listed;
    });
    // Every path below awaits the read. This handler only covers the posts.
    read.catch(() => undefined);

    const posts: DirectIntentPosts = { accepted: new Map(), refused: new Map() };
    const control: DevicePostControl = {
      ...(stopSignal && { stopSignal }),
      admit: () => {
        if (arrived.listed) throw new DeferredPost();
      },
    };
    try {
      await this.sendPhase(
        intent.deviceMessages,
        async (message) => {
          try {
            posts.accepted.set(
              message.recipientDeviceId,
              await this.sendStoredDirectDeviceMessage(intent, message, control)
            );
          } catch (error) {
            if (error instanceof DeferredPost) return;
            if (!isRefusalOfDevice(error, message)) throw error;
            posts.refused.set(message.recipientDeviceId, { error });
          }
        },
        'device',
        stopSignal
      );
    } catch (error) {
      // The read commits sessions. It ends before the send fails.
      await read.catch(() => undefined);
      throw error;
    }

    const list = await read;
    const reconciled = list
      ? await this.reconcileDirectIntent(intent, list, plaintextBytes)
      : intent;
    return this.sendStoredDirectIntent(reconciled, plaintextBytes, sessions, stopSignal, posts);
  }

  /** A replay whose first attempt posted before its read reads and reconciles first. */
  private async reconcilePendingDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined
  ): Promise<StoredOutgoingMessageIntent> {
    if (!intent.reconcilePending || !sessions || !this.relay) return intent;
    const list = await this.readRecipientDeviceList(
      intent.recipientId,
      sessions,
      await this.hasActiveSession(intent.recipientId)
    );
    return list ? this.reconcileDirectIntent(intent, list, plaintextBytes) : intent;
  }

  /**
   * Apply a device-list read to a direct intent: remove each device that the
   * list does not show, and encrypt the message for each established device
   * that the intent does not address. A new transmission keeps the intent's
   * timestamp, so each device receives the same message.
   */
  private async reconcileDirectIntent(
    intent: StoredOutgoingMessageIntent,
    list: RecipientDeviceList,
    plaintextBytes: Uint8Array
  ): Promise<StoredOutgoingMessageIntent> {
    const removed = intent.deviceMessages
      .map((message) => message.recipientDeviceId)
      .filter((deviceId) => !list.listed.has(deviceId));
    const addressed = new Set(intent.deviceMessages.map((message) => message.recipientDeviceId));
    const added: StoredOutgoingDeviceMessage[] = [];
    let sealedSender: ResolvedSealedSenderContext | null | undefined;
    for (const deviceId of list.established) {
      if (addressed.has(deviceId)) continue;
      let message: SesameMessage;
      try {
        message = await this.sesameManager.sendMessage(intent.recipientId, deviceId, plaintextBytes, {
          clientTimestamp: intent.clientTimestamp,
          includeSyncMessages: false,
        });
      } catch (error) {
        this.logger.warn('Could not encrypt a direct message for a newly listed device', {
          category: 'E2EE',
          error: error as Error,
          data: { recipientUserId: intent.recipientId, deviceId },
        });
        continue;
      }
      if (sealedSender === undefined) {
        sealedSender = await this.resolveStoredDirectSealedSender(intent);
      }
      added.push(await this.prepareStoredDirectDeviceMessage(message, sealedSender));
    }
    if (removed.length === 0 && added.length === 0) return intent;
    return reconcileOutgoingDirectDeviceMessages(
      this.storage,
      intent.clientMessageId,
      removed,
      added
    );
  }

  /** The sealed-sender context of a new transmission for a stored direct intent. */
  private async resolveStoredDirectSealedSender(
    intent: StoredOutgoingMessageIntent
  ): Promise<ResolvedSealedSenderContext | null> {
    if (intent.transportMode === 'identified') return null;
    const sealedSender = await this.resolveSealedSenderContext(intent.recipientId);
    if (!sealedSender || sealedSender.auth.type !== 'accessKey') {
      throw new Error('Cannot build a sealed-sender transmission for a stored direct intent');
    }
    return sealedSender;
  }

  private async prepareStoredDirectDeviceMessage(
    message: import('../internal/sesame/types').SesameMessage,
    sealedSender: ResolvedSealedSenderContext | null
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

  /**
   * Refresh the session of a rejected device and replace its transmission.
   * The device posts of a send run at the same time, so the repairs for one
   * recipient take turns: the first session commit with a user pins the
   * user's contact identity, and a concurrent commit that read the store
   * before it fails.
   */
  private async repairRejectedDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined
  ): Promise<StoredOutgoingDeviceMessage> {
    if (!sessions) throw new Error('Stale-session refresh is not configured');
    return this.lock.acquire(`direct-repair:${rejected.recipientUserId}`, () =>
      this.repairRejectedDirectDeviceMessageInTurn(intent, rejected, plaintextBytes, sessions)
    );
  }

  private async repairRejectedDirectDeviceMessageInTurn(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks
  ): Promise<StoredOutgoingDeviceMessage> {
    const refreshed = await sessions.refreshStaleSession(
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
    const replacement = await this.prepareStoredDirectDeviceMessage(
      freshMessage,
      await this.resolveStoredDirectSealedSender(intent)
    );
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
    message: StoredOutgoingDeviceMessage,
    control: DevicePostControl
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
          intent.clientMessageId,
          undefined,
          control
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
          },
          control
        );
  }

  /** Post one device message, and repair its session once if the device rejects it. */
  private async postStoredDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    control: DevicePostControl,
    refusal?: { error: unknown }
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    let rejection: unknown;
    if (refusal) {
      rejection = refusal.error;
    } else {
      try {
        return await this.sendStoredDirectDeviceMessage(intent, message, control);
      } catch (error) {
        rejection = error;
      }
    }
    if (!isConclusiveDeviceRejection(rejection)) throw rejection;
    const replacement = await this.repairRejectedDirectDeviceMessage(
      intent,
      message,
      plaintextBytes,
      sessions
    );
    return this.sendStoredDirectDeviceMessage(intent, replacement, control);
  }

  /**
   * Post each device message of a direct intent, then the sync messages, and
   * complete the intent. A device that a send-first pass already posted keeps
   * its result or its refusal.
   */
  private async sendStoredDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined,
    posts?: DirectIntentPosts
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

    const relay = this.relay;
    let messageId = `local-${intent.clientTimestamp}`;
    let timestamp = intent.clientTimestamp;
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };

    const results = await this.sendPhase(
      intent.deviceMessages,
      async (msg) =>
        posts?.accepted.get(msg.recipientDeviceId) ??
        this.postStoredDirectDeviceMessage(
          intent,
          msg,
          plaintextBytes,
          sessions,
          control,
          posts?.refused.get(msg.recipientDeviceId)
        ),
      'device',
      stopSignal
    );
    for (const result of results) {
      if (messageId.startsWith('local-')) {
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
      }
    }

    // The sync copies start only after every device post settled.
    await this.sendPhase(
      intent.syncMessages,
      (msg) =>
        this.fanOut.request(
          () =>
            relay.send({
              targetUserId: msg.recipientUserId,
              targetDeviceId: msg.recipientDeviceId,
              senderUserId: this.userId,
              senderDeviceId: this.deviceId,
              ciphertext: msg.ciphertext,
              messageType: msg.messageType,
              deliveryClass: 'background-sync',
              timestamp: msg.timestamp,
              clientMessageId: msg.clientMessageId,
            }),
          stopSignal
        ),
      'sync',
      stopSignal
    );

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
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };
    return sendGroupWithExactOutbox(
      {
        storage: this.storage,
        ...(this.relay && { relay: this.relay }),
        senderUserId: this.userId,
        senderDeviceId: this.deviceId,
        deliveryMode: this.sealedSenderDeliveryMode,
        preparePayload: async (groupId, bytes, sendOptions, readMembers) => {
          const prepared = await this.prepareGroupSenderKeyPayload(
            groupId,
            bytes,
            sendOptions,
            sessions,
            readMembers,
            stopSignal
          );
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
          this.resolveGroupMemberDevices(groupId, sendOptions, stopSignal),
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
            },
            control
          ),
        prepareEach: (items, task) =>
          this.fanOut.all(items, task).catch((error: unknown) => {
            throw firstItemError(error);
          }),
        sendPhase: (messages, task, phase) => this.sendPhase(messages, task, phase, stopSignal),
        postToRelay: (send, sealed) => this.postToRelay(send, sealed, control),
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
    const manager = this.endorsementManagerResolver ? await this.endorsementManagerResolver() : this.endorsementManager;
    if (!manager || recipientUserIds.length === 0) return null;
    // The device posts of a send run at the same time. The lock makes them
    // check and refresh the group's endorsements one at a time, so one
    // refresh serves them all. The lock is taken before a slot.
    await this.lock.acquire(`group-send-endorsements:${groupId}`, async () => {
      const { needsRefresh, reason } = await manager.shouldRefreshEndorsements(
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
    });
    const groupSecretParams = this.groupSecretParamsProvider
      ? await this.groupSecretParamsProvider(groupId)
      : null;
    const combined = await manager.getCombinedToken(
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
    const manager = groupId && this.endorsementManagerResolver ? await this.endorsementManagerResolver() : this.endorsementManager;
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
        ...(manager && {
          endorsementManager: manager,
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
    },
    control: DevicePostControl = {}
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    const effectiveClientMessageId = msg.clientMessageId ?? clientMessageId;
    // A fallback continues a post that started, so only the first request is
    // admitted.
    let identifiedControl = control;

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

      identifiedControl = { ...(control.stopSignal && { stopSignal: control.stopSignal }) };
      try {
        const result = await this.postToRelay(
          () =>
            this.relay!.sendMultiRecipientUnidentified!(
              prepared.sentMessageBase64,
              prepared.auth,
              msg.timestamp,
              'user-visible',
              [msg.recipientUserId],
              effectiveClientMessageId
            ),
          true,
          control
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
            const contactProfileStateStore = this.contactProfileStateStore;
            if (contactProfileStateStore) {
              // The device posts of a send run at the same time. The lock
              // orders their steps, so two failures step down twice, as posts
              // in device order do.
              await this.lock.acquire(
                `unidentified-access-mode:${msg.recipientUserId}`,
                async () => {
                  const currentMode = await contactProfileStateStore.getUnidentifiedAccessMode(
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
                  await contactProfileStateStore.updateUnidentifiedAccessMode(
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
    return this.postToRelay(
      () =>
        this.relay!.send({
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
        }),
      false,
      identifiedControl
    );
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
    options: SendOptions | undefined,
    stopSignal: AbortSignal | undefined
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
    const deviceResults = await this.fanOut
      .all(
        options.groupMemberUserIds,
        (userId) => this.fanOut.request(() => this.relay!.getActiveDevices(userId), stopSignal),
        stopSignal
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });
    return deviceResults.flat();
  }

  private async prepareGroupSenderKeyPayload(
    actualGroupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number },
    sessions: SendSessionCallbacks | undefined,
    readMembers: () => Promise<GroupMemberDevice[]>,
    stopSignal: AbortSignal | undefined
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
      const members = await readMembers();
      const otherMembers = members.filter((member) => member.userId !== this.userId);
      const recipientUserIds = [...new Set(otherMembers.map((member) => member.userId))];
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
      // The recipients are prepared at the same time. The session work of one
      // recipient stays in turn, and its session setup reuses the devices that
      // this send read.
      const prepared = await this.fanOut
        .all(
          recipientUserIds,
          async (recipientUserId) => {
            await this.ensureSessionsForUser(
              recipientUserId,
              sessions,
              false,
              otherMembers.filter((member) => member.userId === recipientUserId)
            );
            const batch = await this.sesameManager.send(recipientUserId, skdmBytes, {
              clientTimestamp: options.timestamp,
              includeSyncMessages: false,
            });
            const stored: StoredOutgoingDeviceMessage[] = [];
            for (const message of batch.deviceMessages) {
              stored.push(await this.prepareStoredDirectDeviceMessage(message, null));
            }
            return stored;
          },
          stopSignal
        )
        .catch((error: unknown) => {
          throw firstItemError(error);
        });
      // The index of each pre-message follows the recipient order.
      for (const stored of prepared.flat()) {
        stored.clientMessageId = `${options.clientMessageId}:sender-key-distribution:${preMessages.length}`;
        preMessages.push(stored);
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
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    // The group operation owns preparation, persistence, posting, and key confirmation.
    return this.groupSenderKeys.run(
      groupId,
      async (actualGroupId) => {
        await this.groupSendBarrierChecker?.(actualGroupId);
        return this.encryptToGroupWithOutbox(
          actualGroupId,
          plaintextBytes,
          options,
          sessions,
          stopSignal
        );
      },
      stopSignal
    );
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
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
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
      result = await this.encryptToGroup(
        recipientId,
        attachmentBytes,
        options,
        sessions,
        stopSignal
      );
    } else {
      result = await this.encryptToUser(recipientId, attachmentBytes, options, sessions);
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
        'Remote object storage not configured. Provide remoteObjectStore in DefaultSignalProtocolClient.create() config.',
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
