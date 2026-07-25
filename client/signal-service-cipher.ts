/**
 * SignalServiceCipher - Cipher coordination for Signal Protocol
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
  ISignalRelayServer,
  Envelope,
  StaleSessionErrorData,
  SealedSenderAuth,
  GroupMemberDevice,
} from '../remote/relay/types';
import type { SignalRemoteObjectStore } from '../remote/object-store';
import type { ISignalLocalStore, Base64 } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import { base64ToBytes } from '../internal/crypto';
import type { DecryptedEnvelope } from './event-hooks';
import { recordServerClockSample } from '../server-clock';
import { ProtocolAddress } from '../types/address';
import type { ISesameManager, SesameMessage, OutgoingMessageBatch } from '../internal/sesame/types';
import { defaultSignalLogger, type ILogger } from '../logger';
import { SenderKeyManager } from '../internal/protocol/sender-keys';
import { isGroupId, extractGroupId } from '../internal/groups';
import type { EndorsementManager } from './endorsement-manager';
import type { PreparedAttachmentUpload, SendOptions, SendResult } from './types';
import { ContentHint } from '../types/messages';
import {
  type BlockedRecipientsSyncInput,
  createDefaultSignalContentAdapter,
  type ConfigurationSyncInput,
  type MediaAttachmentDeleteSyncInput,
  type ReadSyncEntryInput,
  type RecipientUsernameSyncInput,
  type SignalContentAdapter,
  type TaskNotificationAckSyncInput,
  type UsernameStateSyncInput,
  type VerificationStateSyncInput,
  type ViewOnceOpenSyncInput,
} from './content-adapter';
import * as CryptoUtils from '../internal/crypto';
import { withRetry } from '../utils/retry';
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
 * ciphertexts that depend on those sessions. This ensures SESAME session
 * convergence works correctly.
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
      // PreKeySignalMessage: first tag is 0x08 (field 1 uint32) or 0x12 (field 2 bytes)
      if (firstTag === 0x08 || firstTag === 0x12) {
        return 'prekey_bundle';
      }
    }
  } catch {
    // Not valid base64 binary
  }

  return 'ciphertext';
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

/**
 * Detect 409 mismatched devices error from V2 multi-recipient send.
 *
 * Server returns this when the device list in the request doesn't match
 * the recipient's current device list (device added/removed since last check).
 * Our Convex server throws errors with 'MISMATCHED_DEVICES' in the message.
 *
 */
function isMismatchedDevicesError(message: string): boolean {
  return message.includes('MISMATCHED_DEVICES');
}

/**
 * Detect 410 stale sessions error from V2 multi-recipient send.
 *
 * Server returns this when registration IDs in the request don't match
 * (device was reinstalled). Sessions need to be archived and re-established.
 * Our Convex server throws errors with 'STALE_DEVICE' in the message.
 *
 */
function isStaleSessionV2Error(message: string): boolean {
  return message.includes('STALE_DEVICE');
}

/**
 * Sealed sender context provider callback
 *
 * Provides the sender certificate and identity key pair needed for sealing.
 * Injected by SignalProtocolClient so the cipher doesn't need to manage certificate
 * caching or key lookup directly.
 *
 * @returns Sender certificate (base64), sender private key (bytes), and config
 */
export type SealedSenderProvider = () => Promise<{
  senderCertificateBase64: string;
  senderIdentityPrivate: Uint8Array;
  senderIdentityPublic: Uint8Array;
  config: import('./config').SealedSenderConfig;
}>;

/**
 * Callback for establishing sessions when none exist
 * Allows SignalProtocolClient to inject its session establishment logic
 */
export type SessionEstablisher = (recipientUserId: string) => Promise<{
  establishedDevices: number[];
  failedDevices: number[];
  failedDeviceErrors?: Array<{ deviceId: number; error: Error }>;
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

/**
 * SignalServiceCipher - Routes encryption and decryption to appropriate ciphers
 *
 * Handles:
 * - Pairwise messages via SESAME/Double Ratchet
 * - Group messages via Sender Keys
 * - Binary content with two-layer encryption (AES-GCM + Signal Protocol)
 *
 * @example
 * ```typescript
 * // Created by SignalProtocolClient - not instantiated directly
 * const cipher = new SignalServiceCipher(userId, deviceId, sesameManager, ...);
 *
 * // Decrypt incoming envelope
 * const decrypted = await cipher.decrypt(envelope);
 *
 * // Encrypt outgoing message
 * const result = await cipher.encrypt('bob', 'Hello!');
 * ```
 */
export class SignalServiceCipher {
  private readonly lock = new AsyncLock();
  private sessionEstablisher?: SessionEstablisher;
  private staleSessionRefresher?: StaleSessionRefresher;
  private sealedSenderProvider?: SealedSenderProvider;
  private contactProfileStateStore?: ContactProfileStateStore;
  private endorsementManager?: EndorsementManager;
  private endorsementRefresher?: EndorsementRefresher;
  private groupSecretParamsProvider?: (
    groupId: string
  ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>;

  constructor(
    private readonly userId: string,
    private readonly deviceId: number,
    private readonly sesameManager: ISesameManager,
    private readonly senderKeyManager: SenderKeyManager,
    private readonly storage: ISignalLocalStore,
    private readonly relay?: ISignalRelayServer,
    private readonly remoteObjectStore?: SignalRemoteObjectStore,
    private readonly contentAdapter?: SignalContentAdapter,
    private readonly logger: Required<ILogger> = defaultSignalLogger
  ) {}

  private getResolvedContentAdapter(): SignalContentAdapter {
    return this.contentAdapter ?? createDefaultSignalContentAdapter();
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
        timestamp: syncMsg.timestamp,
      });
    }
  }

  private async sendSyncTranscriptToLocalOtherDevices(
    conversationId: string,
    plaintextBytes: Uint8Array,
    timestamp: number,
    recipientUserId?: string
  ): Promise<void> {
    const transcriptBytes = this.buildSentSyncTranscript(
      conversationId,
      plaintextBytes,
      timestamp,
      recipientUserId
    );
    await this.sendSyncPayloadToLocalOtherDevices(transcriptBytes, timestamp);
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

      const { unsealMessage, reconstructEnvelope } = await import('./sealed-sender-ops');

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
        this.logger
      );

      // Reconstruct envelope with revealed sender identity
      const innerEnvelope = reconstructEnvelope(envelope, unsealed);

      // Recursively decrypt the inner message (now a standard ciphertext)
      return this.decrypt(innerEnvelope);
    }

    // Validate message type before processing
    // Server only sends the 5 envelope types; client-to-client types (typing_indicator,
    // delivery_receipt, sender_key_distribution) are encrypted Content inside ciphertext.
    const validMessageTypes = [
      'prekey_bundle',
      'ciphertext',
      'plaintext_content',
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
          groupId: envelope.groupId,
        },
      });

      let plaintext: string;

      // Route to appropriate decryption based on context
      // Group messages arrive as 'ciphertext' with groupId set (the server doesn't
      // distinguish group vs pairwise — both are ciphertext envelopes)
      if (envelope.groupId && envelope.messageType === 'ciphertext') {
        // Group message encrypted with Sender Keys
        plaintext = await this.decryptGroup(envelope);
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
        envelope.groupId ||
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
        isGroup: !!envelope.groupId,
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
   * @param recipientId - User ID or group ID (groups use the V2 group ID prefix)
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
    const lockKey = `encrypt:${recipientId}`;

    return this.lock.acquire(lockKey, async () => {
      // 1. Route binary file data (Uint8Array with isBinary flag) to blob encryption
      if (options?.isBinary) {
        return this.encryptBinaryAttachment(recipientId, content, options);
      }

      // 2. Detect recipient type (group vs user)
      if (isGroupId(recipientId)) {
        return this.encryptToGroup(recipientId, content, options);
      }

      // 3. Send to user (existing SESAME path)
      return this.encryptToUser(recipientId, content, options);
    });
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
   * Decrypt a group message via Sender Keys
   *
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  private async decryptGroup(envelope: Envelope): Promise<string> {
    // Get the framed SenderKeyMessage bytes
    let framedBytes: Uint8Array;
    if (typeof envelope.ciphertext === 'string') {
      // Base64-encoded framed SenderKeyMessage
      framedBytes = CryptoUtils.base64ToBytes(envelope.ciphertext as Base64);
    } else {
      framedBytes = envelope.ciphertext;
    }

    try {
      const plaintext = await this.senderKeyManager.decryptGroupMessage(
        envelope.groupId!,
        envelope.senderUserId,
        envelope.senderDeviceId,
        framedBytes
      );

      this.logger.debug('Decrypted group message', {
        category: 'E2EE',
        data: {
          groupId: envelope.groupId,
          senderId: envelope.senderUserId,
        },
      });

      return plaintext;
    } catch (error) {
      const err = error as Error;
      if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
        throw new EncryptionError(
          `No sender key from ${envelope.senderUserId} for group ${envelope.groupId} - request key distribution`,
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
   * Ensure sessions exist with a recipient user
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
      result = await withRetry(() => this.sessionEstablisher!(recipientUserId), {
        operationName: 'establishSession',
        maxRetries: 2,
        baseDelay: 500,
      });
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
      const firstDeviceError = result.failedDeviceErrors?.[0]?.error;
      if (firstDeviceError) {
        throw firstDeviceError;
      }
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
    options?: SendOptions
  ): Promise<SendResult> {
    // Auto-establish sessions if needed (lazy session creation)
    await this.ensureSessionsForUser(recipientUserId);

    // SESAME multi-device encryption: encrypt for all recipient devices
    let batch: OutgoingMessageBatch;
    try {
      const clientTimestamp = options?.timestamp ?? Date.now();
      const syncPlaintext = this.buildSentSyncTranscript(
        this.getDirectConversationId(recipientUserId),
        plaintextBytes,
        clientTimestamp,
        recipientUserId
      );
      batch = await this.sesameManager.send(recipientUserId, plaintextBytes, {
        clientTimestamp,
        syncPlaintext,
      });
    } catch (error) {
      // Preserve EncryptionError codes
      if (error instanceof EncryptionError) {
        throw error;
      }
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

    // Upload messages to relay server if configured
    let messageId = `local-${Date.now()}`;
    let timestamp = Date.now(); // Fallback if no relay

    if (this.relay) {
      // Resolve sealed sender context once per send (avoid re-fetching per device)
      const sealedSender = await this.resolveSealedSenderContext(recipientUserId);

      // Send to each recipient device with stale session handling
      for (const msg of batch.deviceMessages) {
        const messageType = getEnvelopeMessageType(msg.ciphertext);
        const ciphertextBase64 =
          typeof msg.ciphertext === 'string'
            ? msg.ciphertext
            : CryptoUtils.bytesToBase64(msg.ciphertext);

        // For PreKeyMessages, get session metadata for server-side validation
        // The reference implementation only validates registrationId server-side (device reinstall detection)
        // Stale prekey detection is handled client-side via MAC failure + retry
        let recipientRegistrationId: number | undefined;

        if (messageType === 'prekey_bundle') {
          const session = await this.sesameManager.getSession(
            msg.recipientUserId,
            msg.recipientDeviceId
          );
          if (session?.currentSession) {
            recipientRegistrationId = session.currentSession.remoteRegistrationId;
          }
        }

        try {
          const result = await this.sendToDevice(
            msg,
            ciphertextBase64,
            messageType,
            recipientRegistrationId,
            sealedSender,
            options?.contentHint,
            options?.clientMessageId
          );
          // Use first envelope ID and serverTimestamp as the canonical values
          if (messageId.startsWith('local-')) {
            messageId = result.messageId;
            timestamp = result.serverTimestamp;
          }
        } catch (error) {
          // Recover from a relay stale-device response.
          if (isStaleSessionError(error) && this.staleSessionRefresher) {
            const staleData = error.data;
            this.logger.info('Server detected stale session, refreshing', {
              category: 'E2EE',
              data: {
                code: staleData.code,
                reason: staleData.reason,
                recipientUserId: msg.recipientUserId,
                recipientDeviceId: msg.recipientDeviceId,
              },
            });

            // Refresh the stale session (archive + fetch fresh bundle + re-establish)
            const refreshed = await this.staleSessionRefresher(
              msg.recipientUserId,
              msg.recipientDeviceId
            );

            if (refreshed) {
              // Re-encrypt and retry with fresh session
              const freshBatch = await this.sesameManager.send(recipientUserId, plaintextBytes, {
                clientTimestamp: options?.timestamp,
              });
              const freshMsg = freshBatch.deviceMessages.find(
                (m) =>
                  m.recipientUserId === msg.recipientUserId &&
                  m.recipientDeviceId === msg.recipientDeviceId
              );

              if (freshMsg) {
                const freshCiphertext =
                  typeof freshMsg.ciphertext === 'string'
                    ? freshMsg.ciphertext
                    : CryptoUtils.bytesToBase64(freshMsg.ciphertext);

                // Get fresh session metadata
                const freshSession = await this.sesameManager.getSession(
                  msg.recipientUserId,
                  msg.recipientDeviceId
                );

                const retryResult = await this.sendToDevice(
                  freshMsg,
                  freshCiphertext,
                  getEnvelopeMessageType(freshMsg.ciphertext),
                  freshSession?.currentSession?.remoteRegistrationId,
                  sealedSender,
                  options?.contentHint,
                  options?.clientMessageId
                );

                if (messageId.startsWith('local-')) {
                  messageId = retryResult.messageId;
                  timestamp = retryResult.serverTimestamp;
                }

                this.logger.info('Successfully sent after stale session refresh', {
                  category: 'E2EE',
                  data: {
                    recipientUserId: msg.recipientUserId,
                    recipientDeviceId: msg.recipientDeviceId,
                  },
                });
                continue; // Successfully sent after refresh
              }
            }

            // If refresh failed or no message for device, throw original error
            throw new EncryptionError(
              `Failed to refresh stale session: ${staleData.reason}`,
              EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
              {
                originalError: error as unknown as Error,
                recipientUserId: msg.recipientUserId,
              }
            );
          }

          // Re-throw non-stale errors
          throw error;
        }
      }

      await this.uploadSyncMessages(batch.syncMessages);
    }

    return {
      messageId,
      timestamp,
      recipientDeviceCount: batch.deviceMessages.length,
    };
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
   * @param groupId - Optional group ID; when provided, endorsement-based auth is attempted first
   *
   */
  private async resolveSealedSenderContext(
    recipientUserId: string,
    groupId?: string
  ): Promise<{
    senderCertificateBase64: string;
    senderIdentityPrivate: Uint8Array;
    recipientIdentityPublic: Uint8Array;
    config: import('./config').SealedSenderConfig;
    auth: SealedSenderAuth;
  } | null> {
    if (!this.sealedSenderProvider || !this.relay?.sendUnidentified) {
      return null;
    }

    try {
      // Priority 1: GroupSend endorsement (preferred for groups)
      // No profile key needed — endorsement tokens prove group membership via ZK credential
      if (groupId && this.endorsementManager) {
        try {
          // Resolve group secret params for endorsement token generation
          const groupSecretParams = this.groupSecretParamsProvider
            ? await this.groupSecretParamsProvider(groupId)
            : null;
          const endorsementToken = await this.endorsementManager.getTokenForRecipient(
            groupId,
            recipientUserId,
            groupSecretParams ?? undefined
          );
          if (endorsementToken) {
            const { senderCertificateBase64, senderIdentityPrivate, config } =
              await this.sealedSenderProvider();

            const recipientAddress = ProtocolAddress.create(recipientUserId, 1);
            const recipientIdentityRecord = await this.storage.getContactIdentity(recipientAddress);

            if (recipientIdentityRecord) {
              const recipientIdentityPublic = base64ToBytes(
                recipientIdentityRecord.identity.x25519PublicKey
              );
              return {
                senderCertificateBase64,
                senderIdentityPrivate,
                recipientIdentityPublic,
                config,
                auth: {
                  type: 'groupSendToken',
                  groupSendToken: endorsementToken.token,
                },
              };
            }
          }
        } catch (endorsementError) {
          // Endorsement lookup failed — fall through to UAK path
          this.logger.debug('Endorsement lookup failed, trying UAK', {
            category: 'E2EE',
            data: {
              recipientUserId,
              groupId,
              error: (endorsementError as Error).message,
            },
          });
        }
      }

      // Priority 2: Per-contact mode-based UAK (existing path)
      // Check mode first — DISABLED skips sealed sender entirely
      const contactStateStore = this.contactProfileStateStore;
      if (!contactStateStore) {
        this.logger.debug('No contact profile state store configured, using identified delivery', {
          category: 'E2EE',
          data: { recipientUserId, groupId },
        });
        return null;
      }

      const mode = await contactStateStore.getUnidentifiedAccessMode(recipientUserId);

      if (mode === UnidentifiedAccessMode.DISABLED) {
        this.logger.debug('Sealed sender disabled for recipient, using identified delivery', {
          category: 'E2EE',
          data: { recipientUserId, mode },
        });
        return null;
      }

      // Resolve access key based on mode
      const { deriveAccessKey } = await import('../internal/protocol/sealed-sender/delivery-token');
      const { bytesToBase64 } = await import('../internal/crypto');

      let auth: SealedSenderAuth;

      switch (mode) {
        case UnidentifiedAccessMode.UNRESTRICTED: {
          // Anyone can send sealed sender — use zeroed 16-byte key
          const zeroedKey = new Uint8Array(16);
          auth = {
            type: 'accessKey',
            unidentifiedAccessKey: bytesToBase64(zeroedKey),
          };
          break;
        }
        case UnidentifiedAccessMode.ENABLED: {
          // Must derive from profile key — fail if unavailable
          const recipientProfileKey = await contactStateStore.getContactProfileKey(recipientUserId);
          if (!recipientProfileKey) {
            this.logger.debug('No profile key for ENABLED recipient, using identified delivery', {
              category: 'E2EE',
              data: { recipientUserId },
            });
            return null;
          }
          const accessKey = await deriveAccessKey(recipientProfileKey);
          auth = {
            type: 'accessKey',
            unidentifiedAccessKey: bytesToBase64(accessKey),
          };
          break;
        }
        case UnidentifiedAccessMode.UNKNOWN:
        default: {
          // Best effort: use derived key if available, else zeroed key
          const recipientProfileKey = await contactStateStore.getContactProfileKey(recipientUserId);
          if (recipientProfileKey) {
            const accessKey = await deriveAccessKey(recipientProfileKey);
            auth = {
              type: 'accessKey',
              unidentifiedAccessKey: bytesToBase64(accessKey),
            };
          } else {
            const zeroedKey = new Uint8Array(16);
            auth = {
              type: 'accessKey',
              unidentifiedAccessKey: bytesToBase64(zeroedKey),
            };
          }
          break;
        }
      }

      // Get sender certificate and identity keys
      const { senderCertificateBase64, senderIdentityPrivate, config } =
        await this.sealedSenderProvider();

      // Get recipient's identity public key (needed for sealed sender DH)
      const recipientAddress = ProtocolAddress.create(recipientUserId, 1);
      const recipientIdentityRecord = await this.storage.getContactIdentity(recipientAddress);
      if (!recipientIdentityRecord) {
        // No identity key on file - fall back to identified delivery
        this.logger.debug('No identity key for recipient, using identified delivery', {
          category: 'E2EE',
          data: { recipientUserId },
        });
        return null;
      }

      const recipientIdentityPublic = base64ToBytes(
        recipientIdentityRecord.identity.x25519PublicKey
      );

      return {
        senderCertificateBase64,
        senderIdentityPrivate,
        recipientIdentityPublic,
        config,
        auth,
      };
    } catch (error) {
      // Sealed sender is best-effort; fall back to identified delivery on failure
      this.logger.warn('Failed to resolve sealed sender context, using identified delivery', {
        category: 'E2EE',
        data: { recipientUserId, error: (error as Error).message },
      });
      return null;
    }
  }

  /**
   * Send a single ciphertext to a device, optionally wrapping with sealed sender.
   *
   * When sealed sender context is available:
   * 1. Wraps the ciphertext with seal() to hide sender identity
   * 2. Uses relay.sendUnidentified() for anonymous delivery
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
      groupId?: string;
      clientMessageId?: string;
    },
    ciphertextBase64: string,
    messageType: 'prekey_bundle' | 'ciphertext',
    recipientRegistrationId: number | undefined,
    sealedSender: Awaited<
      ReturnType<typeof SignalServiceCipher.prototype.resolveSealedSenderContext>
    >,
    contentHint?: ContentHint,
    clientMessageId?: string
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    const effectiveClientMessageId = msg.clientMessageId ?? clientMessageId;

    // Sealed sender path: wrap with seal() and use anonymous delivery
    if (sealedSender && this.relay!.sendUnidentified) {
      const { sealMessage } = await import('./sealed-sender-ops');

      const sealedCiphertext = await sealMessage(
        ciphertextBase64,
        sealedSender.senderCertificateBase64,
        sealedSender.senderIdentityPrivate,
        sealedSender.recipientIdentityPublic,
        sealedSender.config,
        this.logger
      );

      try {
        return await this.relay!.sendUnidentified!(
          {
            targetUserId: msg.recipientUserId,
            targetDeviceId: msg.recipientDeviceId,
            senderUserId: '', // Hidden from server
            senderDeviceId: 0,
            ciphertext: sealedCiphertext,
            messageType: 'unidentified_sender',
            groupId: msg.groupId,
            timestamp: msg.timestamp,
            clientMessageId: effectiveClientMessageId,
            contentHint,
          },
          sealedSender.auth
        );
      } catch (error) {
        // Fall back to identified delivery only for sealed-sender authorization
        // failures. Other failures retain their original error semantics.
        if (error instanceof SealedSenderAuthError) {
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
            // Non-fatal: mode transition failure shouldn't block message delivery
            this.logger.warn('Failed to update unidentified access mode after auth failure', {
              category: 'E2EE',
              data: {
                recipientUserId: msg.recipientUserId,
                error: (modeError as Error).message,
              },
            });
          }
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
      groupId: msg.groupId,
      timestamp: msg.timestamp,
      clientMessageId: effectiveClientMessageId,
      recipientRegistrationId,
      contentHint,
    });
  }

  /**
   * Attempt V2 multi-recipient sealed sender send.
   * Returns null if unavailable — caller falls back to V1.
   *
   * Recovery behavior:
   * - 409 (mismatched devices): refresh device lists, rebuild recipient list, retry once
   * - 410 (stale sessions): archive stale sessions, retry once
   * - Other errors: return null for full V1 fallback
   *
   */
  private async tryMultiRecipientSend(
    groupId: string,
    otherMembers: GroupMemberDevice[],
    encryptedMessageJson: string,
    sendTimestamp: number,
    clientMessageId?: string
  ): Promise<{ messageId: string; serverTimestamp: number } | null> {
    // Guard checks — return null to trigger V1 fallback
    if (!this.sealedSenderProvider) return null;
    if (!this.relay?.sendMultiRecipientUnidentified) return null;
    if (otherMembers.length < 2) return null;

    // outer recovery state flags — prevent infinite retry loops
    //
    let hasRetriedDevices = false;
    let hasRetriedSessions = false;
    let currentMembers = otherMembers;

    const attemptV2Send = async (): Promise<{
      messageId: string;
      serverTimestamp: number;
    } | null> => {
      // Get sender keys (certificate + identity)
      const senderKeys = await this.sealedSenderProvider!();

      const { base64ToBytes: b64ToBytes, bytesToBase64: bytesToB64 } =
        await import('../internal/crypto');

      // Gather recipient identity keys (per unique userId)
      const identityByUser = new Map<string, Uint8Array>();
      const uniqueUserIds = [...new Set(currentMembers.map((m) => m.userId))];

      for (const userId of uniqueUserIds) {
        const address = ProtocolAddress.create(userId, 1);
        const identityRecord = await this.storage.getContactIdentity(address);
        if (identityRecord) {
          identityByUser.set(userId, b64ToBytes(identityRecord.identity.x25519PublicKey));
        }
      }

      // Split V2-eligible vs V1-fallback
      const v2Members: typeof currentMembers = [];
      const v1FallbackMembers: typeof currentMembers = [];

      for (const member of currentMembers) {
        if (identityByUser.has(member.userId)) {
          v2Members.push(member);
        } else {
          v1FallbackMembers.push(member);
        }
      }

      // Need at least 2 V2-eligible unique users
      const v2UniqueUsers = new Set(v2Members.map((m) => m.userId));
      if (v2UniqueUsers.size < 2) return null;

      // Build V2 recipients with registration IDs from session state
      const v2Recipients: Array<{
        serviceId: string;
        deviceId: number;
        registrationId: number;
        identityPublic: Uint8Array;
      }> = [];

      for (const member of v2Members) {
        const session = await this.storage.getSessionRecord(
          ProtocolAddress.create(member.userId, member.deviceId)
        );

        let registrationId = 0;
        if (session?.currentSession) {
          registrationId = session.currentSession.remoteRegistrationId;
        }

        v2Recipients.push({
          serviceId: member.userId,
          deviceId: member.deviceId,
          registrationId,
          identityPublic: identityByUser.get(member.userId)!,
        });
      }

      // Call sealMultiRecipient()
      const { sealMultiRecipient } = await import('../internal/protocol/sealed-sender');
      const { deserializeSenderCertificate } = await import('../internal/protocol/sealed-sender');

      // Parse sender certificate
      const certBytes = b64ToBytes(senderKeys.senderCertificateBase64 as Base64);
      const senderCertificate = deserializeSenderCertificate(certBytes);

      // Convert encryptedMessageJson to bytes for the seal
      const signalProtocolMessage = new TextEncoder().encode(encryptedMessageJson);

      // Group ID as bytes
      const groupIdBytes = new TextEncoder().encode(groupId);

      const sealResult = await sealMultiRecipient({
        senderCertificate,
        senderIdentityPrivate: senderKeys.senderIdentityPrivate,
        senderIdentityPublic: senderKeys.senderIdentityPublic,
        recipients: v2Recipients,
        signalProtocolMessage,
        groupId: groupIdBytes,
      });

      // Serialize to binary
      const { serializeSentMessage } = await import('../internal/protocol/sealed-sender/v2-binary');

      // Group recipients by serviceId for the binary format
      const recipientsByUser = new Map<
        string,
        {
          serviceId: string;
          devices: Array<{ deviceId: number; registrationId: number }>;
          encryptedMessageKey: Uint8Array;
          authenticationTag: Uint8Array;
        }
      >();

      for (const entry of sealResult.recipients) {
        const existing = recipientsByUser.get(entry.serviceId);
        if (existing) {
          existing.devices.push({
            deviceId: entry.deviceId,
            registrationId: entry.registrationId,
          });
        } else {
          recipientsByUser.set(entry.serviceId, {
            serviceId: entry.serviceId,
            devices: [
              {
                deviceId: entry.deviceId,
                registrationId: entry.registrationId,
              },
            ],
            encryptedMessageKey: b64ToBytes(entry.encryptedMessageKey as Base64),
            authenticationTag: b64ToBytes(entry.authenticationTag as Base64),
          });
        }
      }

      const binaryBlob = serializeSentMessage(
        Array.from(recipientsByUser.values()),
        [], // No excluded recipients for now
        b64ToBytes(sealResult.ephemeralPublic as Base64),
        b64ToBytes(sealResult.messageCiphertext as Base64)
      );

      const sentMessageBase64 = bytesToB64(binaryBlob);

      // Get combined auth token
      if (!this.endorsementManager) return null;

      const groupSecretParams = this.groupSecretParamsProvider
        ? await this.groupSecretParamsProvider(groupId)
        : null;

      const v2UserIds = [...v2UniqueUsers];

      // Pre-send endorsement refresh
      const { needsRefresh, reason } = await this.endorsementManager.shouldRefreshEndorsements(
        groupId,
        v2UserIds
      );

      if (needsRefresh && this.endorsementRefresher) {
        try {
          await this.endorsementRefresher(groupId, v2UserIds);
          this.logger.debug('Refreshed endorsements before V2 send', {
            category: 'E2EE',
            data: { groupId, reason },
          });
        } catch (refreshErr) {
          this.logger.debug('Pre-send endorsement refresh failed, will attempt V1 fallback', {
            category: 'E2EE',
            data: { groupId, error: (refreshErr as Error).message },
          });
        }
      }

      const combinedToken = await this.endorsementManager.getCombinedToken(
        groupId,
        v2UserIds,
        groupSecretParams ?? undefined
      );

      if (!combinedToken) return null;

      const auth: SealedSenderAuth = {
        type: 'groupSendToken',
        groupSendToken: combinedToken.token,
      };

      // Send via relay
      const recipientUserIds = Array.from(recipientsByUser.keys());
      const result = await this.relay!.sendMultiRecipientUnidentified!(
        sentMessageBase64,
        auth,
        sendTimestamp,
        groupId,
        recipientUserIds,
        clientMessageId
      );

      // Send to V1 fallback members via per-device fanout
      if (v1FallbackMembers.length > 0) {
        const sealedSenderByUser = new Map<
          string,
          Awaited<ReturnType<typeof this.resolveSealedSenderContext>>
        >();
        const fallbackUserIds = [...new Set(v1FallbackMembers.map((m) => m.userId))];
        for (const userId of fallbackUserIds) {
          sealedSenderByUser.set(userId, await this.resolveSealedSenderContext(userId, groupId));
        }

        for (const member of v1FallbackMembers) {
          const sealedSender = sealedSenderByUser.get(member.userId) ?? null;
          await this.sendToDevice(
            {
              recipientUserId: member.userId,
              recipientDeviceId: member.deviceId,
              timestamp: sendTimestamp,
              groupId,
            },
            encryptedMessageJson,
            'ciphertext',
            undefined,
            sealedSender,
            undefined,
            clientMessageId
          );
        }
      }

      return {
        messageId: result.messageId,
        serverTimestamp: result.serverTimestamp,
      };
    };

    try {
      return await attemptV2Send();
    } catch (error) {
      const errorMessage = (error as Error).message ?? '';

      // 409: Mismatched devices — refresh device lists and retry once
      // the application send pipeline
      if (!hasRetriedDevices && isMismatchedDevicesError(errorMessage)) {
        hasRetriedDevices = true;
        this.logger.info('V2 send got mismatched devices (409), refreshing and retrying', {
          category: 'E2EE',
          data: { groupId },
        });

        try {
          // Refresh device lists for all affected users
          const uniqueUserIds = [...new Set(currentMembers.map((m) => m.userId))];
          const refreshedDevices = await Promise.all(
            uniqueUserIds.map((uid) => this.relay!.getActiveDevices(uid))
          );
          currentMembers = refreshedDevices.flat().filter((m) => m.userId !== this.userId);

          return await attemptV2Send();
        } catch (retryError) {
          this.logger.debug('V2 retry after device refresh failed, falling back to V1', {
            category: 'E2EE',
            data: { groupId, error: (retryError as Error).message },
          });
          return null;
        }
      }

      // 410: Stale sessions — archive and retry once
      // the application send pipeline
      if (!hasRetriedSessions && isStaleSessionV2Error(errorMessage)) {
        hasRetriedSessions = true;
        this.logger.info('V2 send got stale sessions (410), archiving and retrying', {
          category: 'E2EE',
          data: { groupId },
        });

        try {
          // Archive stale sessions for all affected devices and re-establish
          if (this.staleSessionRefresher) {
            for (const member of currentMembers) {
              await this.staleSessionRefresher(member.userId, member.deviceId).catch(() => {
                // Non-fatal: some devices might not have stale sessions
              });
            }
          }

          return await attemptV2Send();
        } catch (retryError) {
          this.logger.debug('V2 retry after session refresh failed, falling back to V1', {
            category: 'E2EE',
            data: { groupId, error: (retryError as Error).message },
          });
          return null;
        }
      }

      // All other errors: V1 fallback
      this.logger.debug('V2 multi-recipient send failed, falling back to V1', {
        category: 'E2EE',
        data: { groupId, error: errorMessage },
      });
      return null;
    }
  }

  /**
   * V1 per-device sealed sender fanout (legacy path, used as fallback).
   */
  private async perDeviceFanoutSend(
    groupId: string,
    otherMembers: GroupMemberDevice[],
    encryptedMessageJson: string,
    sendTimestamp: number,
    clientMessageId?: string
  ): Promise<{ messageId: string; serverTimestamp: number } | undefined> {
    // Pre-send endorsement freshness check (non-blocking, log only)
    // Actual refresh is handled at orchestration layer (group-service.ts)
    if (this.endorsementManager) {
      const uniqueUserIds = [...new Set(otherMembers.map((m) => m.userId))];
      const { needsRefresh, reason } = await this.endorsementManager.shouldRefreshEndorsements(
        groupId,
        uniqueUserIds
      );
      if (needsRefresh) {
        this.logger.debug('Group endorsements need refresh before send', {
          category: 'E2EE',
          data: { groupId, reason },
        });
      }
    }

    // Resolve sealed sender context per unique recipient (not per device)
    // Identity keys and endorsement tokens are per-user, shared across devices
    const sealedSenderByUser = new Map<
      string,
      Awaited<ReturnType<typeof this.resolveSealedSenderContext>>
    >();
    const uniqueRecipientIds = [...new Set(otherMembers.map((m) => m.userId))];
    for (const userId of uniqueRecipientIds) {
      sealedSenderByUser.set(userId, await this.resolveSealedSenderContext(userId, groupId));
    }

    // Send to each member device (sendToDevice handles seal + fallback)
    let firstResult: { messageId: string; serverTimestamp: number } | undefined;
    for (const member of otherMembers) {
      const sealedSender = sealedSenderByUser.get(member.userId) ?? null;
      const result = await this.sendToDevice(
        {
          recipientUserId: member.userId,
          recipientDeviceId: member.deviceId,
          timestamp: sendTimestamp,
          groupId,
        },
        encryptedMessageJson,
        'ciphertext',
        undefined,
        sealedSender,
        undefined,
        clientMessageId
      );
      if (!firstResult) firstResult = result;
    }

    return firstResult;
  }

  /**
   * Encrypt to a group via Sender Keys (O(1) encryption)
   *
   * Prefers V2 multi-recipient sealed sender when available, falls back to
   * V1 per-device fanout.
   */
  private async encryptToGroup(
    groupId: string,
    plaintextBytes: Uint8Array,
    options?: SendOptions
  ): Promise<SendResult> {
    // Extract actual group ID from prefixed format
    const actualGroupId = extractGroupId(groupId);

    // Require sender key to exist - caller (SignalProtocolClient.createGroupSenderKey) must create it first
    // This ensures proper sender key distribution to group members before sending
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

    // Encrypt with sender key (O(1) - single encryption for all members)
    // Auto-rotate on SENDER_KEY_EXPIRED
    let encrypted: Uint8Array;
    try {
      encrypted = await this.senderKeyManager.encryptGroupMessage(
        actualGroupId,
        this.userId,
        this.deviceId,
        plaintextBytes
      );
    } catch (error) {
      if (
        error instanceof EncryptionError &&
        error.code === EncryptionErrorCode.SENDER_KEY_EXPIRED
      ) {
        this.logger.info('Sender key expired, auto-rotating', {
          category: 'E2EE',
          data: { groupId: actualGroupId },
        });

        // Rotate sender key (generates new key material + increments generation)
        const { distributionMessage } = await this.senderKeyManager.rotateSenderKey(
          actualGroupId,
          this.userId,
          this.deviceId
        );

        // Redistribute new sender key to all group members via relay
        if (this.relay) {
          const members = options?.groupMemberUserIds?.length
            ? (
                await Promise.all(
                  options.groupMemberUserIds.map((uid) => this.relay!.getActiveDevices(uid))
                )
              ).flat()
            : await this.relay.getGroupMembers(actualGroupId);
          const otherMembers = members.filter((m) => m.userId !== this.userId);

          for (const member of otherMembers) {
            // Send SKDM via pairwise session (same as initial distribution)
            await this.ensureSessionsForUser(member.userId);
            // Serialize SKDM as ProtoContentData with senderKeyDistributionMessage field
            // The string field contains JSON-encoded {groupId, ...distributionMessage}
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
            const batch = await this.sesameManager.send(member.userId, skdmBytes, {});
            for (const msg of batch.deviceMessages) {
              const ciphertextBase64 =
                typeof msg.ciphertext === 'string'
                  ? msg.ciphertext
                  : CryptoUtils.bytesToBase64(msg.ciphertext);
              await this.relay.send({
                targetUserId: msg.recipientUserId,
                targetDeviceId: msg.recipientDeviceId,
                senderUserId: this.userId,
                senderDeviceId: this.deviceId,
                ciphertext: ciphertextBase64,
                messageType: getEnvelopeMessageType(msg.ciphertext),
                groupId: actualGroupId,
                timestamp: msg.timestamp,
              });
            }
          }
        }

        // Retry encryption with the new key (once — no infinite loop)
        encrypted = await this.senderKeyManager.encryptGroupMessage(
          actualGroupId,
          this.userId,
          this.deviceId,
          plaintextBytes
        );
      } else {
        throw error;
      }
    }

    // Send encrypted message via relay
    let messageId = `local-${Date.now()}`;
    let timestamp = Date.now(); // Fallback if no relay
    let recipientDeviceCount = 0;

    if (this.relay) {
      // Resolve group members → devices. Prefer caller-provided member list
      // (local-first: membership lives in SQLite, not on server).
      // Falls back to relay.getGroupMembers() for in-memory adapters.
      let members: GroupMemberDevice[];
      if (options?.groupMemberUserIds?.length) {
        const deviceResults = await Promise.all(
          options.groupMemberUserIds.map((userId) => this.relay!.getActiveDevices(userId))
        );
        members = deviceResults.flat();
      } else {
        members = await this.relay.getGroupMembers(actualGroupId);
      }
      // Framed SenderKeyMessage bytes → base64 for transport
      const encryptedMessageJson = CryptoUtils.bytesToBase64(encrypted);
      const sendTimestamp = options?.timestamp ?? Date.now();

      // Filter to other members (skip self — the application send pipeline)
      const otherMembers = members.filter((m) => m.userId !== this.userId);
      recipientDeviceCount = otherMembers.length;

      // Try V2 multi-recipient first
      const v2Result = await this.tryMultiRecipientSend(
        actualGroupId,
        otherMembers,
        encryptedMessageJson,
        sendTimestamp,
        options?.clientMessageId
      );

      if (v2Result) {
        messageId = v2Result.messageId;
        timestamp = v2Result.serverTimestamp;

        this.logger.debug('Group message sent via V2 multi-recipient', {
          category: 'E2EE',
          data: { groupId: actualGroupId, recipientDeviceCount, messageId },
        });
      } else {
        // V1 fallback
        const v1Result = await this.perDeviceFanoutSend(
          actualGroupId,
          otherMembers,
          encryptedMessageJson,
          sendTimestamp,
          options?.clientMessageId
        );

        if (v1Result) {
          messageId = v1Result.messageId;
          timestamp = v1Result.serverTimestamp;
        } else {
          messageId = `group-${actualGroupId}-${timestamp}`;
        }

        this.logger.debug('Group message sent via V1 per-device fanout', {
          category: 'E2EE',
          data: { groupId: actualGroupId, recipientDeviceCount, messageId },
        });
      }

      await this.sendSyncTranscriptToLocalOtherDevices(
        actualGroupId,
        plaintextBytes,
        sendTimestamp
      );
    }

    return {
      messageId,
      timestamp,
      recipientDeviceCount,
      groupId: actualGroupId,
    };
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
    options?: SendOptions
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
      timestamp: options?.timestamp ?? Date.now(),
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
