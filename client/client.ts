/**
 * DefaultSignalProtocolClient - initialized client class for encrypted messaging.
 *
 * @layer 1 - API
 * @boundary SignalProtocolClient
 *
 * Application code should usually create clients with `createSignalProtocolClient()`.
 * Use `DefaultSignalProtocolClient.create()` directly when lower-level integration code already
 * owns the flattened config shape.
 *
 * @example Basic usage
 * ```typescript
 * import { createHostedSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * // Supply a device-local store and the configured identity-provider callback.
 * const signal = await createHostedSignalProtocolClient({
 *   adapters: { storage },
 *   hosted: { relayUrl, getIdentityAssertion },
 * });
 *
 * await signal.send(recipientUserId, 'Hello!');
 * ```
 *
 * @example With product security policy
 * ```typescript
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 *   protocol: { postQuantum: 'required', braid: 'required' },
 * });
 * ```
 *
 * @example Low-level factory
 * ```typescript
 * import { DefaultSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await DefaultSignalProtocolClient.create(userId, {
 *   storage,
 *   relay,
 * });
 * ```
 */

import { initializeManagerFromRetainedIdentities } from '../internal/manager/manager';
import type { RetainedIdentities } from '../internal/manager/retained-identity';
import { ClientStartupCleanupError } from './startup-cleanup';
import { utf8Decode } from '../internal/platform';
import AsyncLock from 'async-lock';
import type { GroupAuthority } from './group-authority';
import type {
  SignalProtocolRelayServer,
  Envelope,
  RelayConnectionState,
  Unsubscribe,
} from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import { DefaultSignalProtocolManager } from '../internal/manager';
import { DefaultSesameManager } from '../internal/sesame';
import type { Ciphertext, IdentityType, PreKeyBundle, PublicKey } from '../keys';
import { createCompositeIdentityV1 } from '../keys/identity';
import type {
  PreKeyRotationResult,
  SendLogDevice,
  SignalProtocolClient,
  SignalProtocolLocalStore,
  SignalProtocolManager,
  Base64,
} from '../types';
import type { ReceiveWorkQuery, ReceiveWorkRecord } from '../types/api';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { ContentHint } from '../types/messages';
import { base64ToBytes, bytesToBase64, constantTimeEqual, generateUuidV4 } from '../internal/crypto';
import { deriveGroupSecretParams, getGroupPublicParams } from '../internal/protocol/zk/groups';
import { SERVICE_ID_ACI } from '../internal/protocol/zk/groups/uid-struct';
import {
  deserializeSenderCertificate,
  validateSenderCertificate,
} from '../internal/protocol/sealed-sender';
import {
  assertHookName,
  callHook,
  deferHooks,
  type SignalProtocolClientHooks,
} from './event-hooks';
import { relayProtocolErrorOf } from './device-set-reconciliation';
import { DeliveryStatusTracker } from './delivery-status';
import { relayReceiptIntakeOf, type RelayDeliveryReceipt } from './relay-receipt-intake';
import { ProtocolAddress } from '../types/address';
import {
  getActiveIdentityTypes,
  resolveSignalProtocolStrategy,
  SEALED_SENDER_CERTIFICATE_MARGIN_MS,
  type ProgressCallback,
  type SignalProtocolClientConfig,
} from './config';
import type { SesameManager, SesameMessage, SesameStats } from '../internal/sesame/types';
import { resolveSignalProtocolLogger, type Logger } from '../logger';
import {
  SenderKeyManager,
  type SenderKeyDistributionMessage,
} from '../internal/protocol/sender-keys';
import {
  type BlockedRecipientsSyncInput,
  createDefaultSignalProtocolContentAdapter,
  type MediaAttachmentDeleteSyncInput,
  type ParsedReceiptContent,
  type GroupContentContext,
  type ParsedTypingContent,
  type ReadSyncEntryInput,
  type RecipientUsernameSyncInput,
  type SignalProtocolContentAdapter,
  type ViewOnceOpenSyncInput,
} from './content-adapter';
// Note: group utilities (isGroupId, extractGroupId, createGroupId) are used by SignalProtocolServiceCipher
import { createGroupId, extractGroupId, isGroupId } from '../internal/groups';
import {
  observeGroupInitStatus,
  readGroupInitStatus,
  type GroupInitStatus,
} from './group-init-status';
import { removeDistributionsFromMessageRecords } from './distribution-records';
import { GroupSenderKeyOperations } from './group-sender-key-operations';
import {
  GroupReceiveRefusedError,
  classifyGroupContent,
  createGroupMembershipChecker,
  createGroupReceiveEvaluator,
  groupOfContext,
  type GroupMembershipChecker,
  type GroupReceiveEvaluator,
} from './group-receive-authorization';
import { GroupFetcher } from './group-fetcher';
import { envelopeCiphertextBytes, receiveRefusal, reportReceiveRefusal } from './delivery-error';
import { profileKeyExchange } from './profile-key-exchange';
import {
  attachClientMessageId,
  SignalProtocolServiceCipher,
  sortEnvelopesForDecryption,
  type SendSessionCallbacks,
} from './signal-service-cipher';
import { establishMultiDeviceSessions } from '../internal/sesame/device-registry';
import { isRetryableDecryptionError } from './retry-utils';
import { envelopeTypeForContent, SealedRetryRequestReceived, unsealMessage } from './sealed-sender';
import { ResendableContent } from './resendable-content';
import {
  decideContentRecovery,
  readLocalStoreProtection,
  resolveContentRecoveryPolicy,
  resolveReceiveQueuePolicy,
  type ResolvedContentRecoveryPolicy,
} from './storage-protection';
import type { ContentRecoveryStatus } from '../types/protocol-config';
import type { DataMessageInput } from './types';

// Import operation modules
import type {
  AttachmentTransferOptions,
  SignalProtocolClientContext,
  SendOptions,
  SendResult,
  SafetyNumber,
  IncomingEnvelope,
  PendingReceive,
  ProcessEnvelopeOptions,
  ProcessedReceive,
  ReceiveOutcome,
} from './types';
import { ReceiptType, TypingAction } from './types';
import * as MessageOps from './messages';
import * as FileOps from './files';
import * as KeyRotationOps from './key-rotation';
import * as SessionOps from './sessions';
import * as GroupOps from './groups';
import * as PreKeyOps from './prekeys';
import * as RetryOps from './retry';
import { receiveInRetryFamily, type RetryFamilyReceive } from './retry-family';
import { RetryRequestScheduler } from './retry-request-lifecycle';
import { ResendJobDriver } from './recovery-driver';
import { retryRequestPost } from './retry-request-envelope';
import type { RetryTerminalResetSteps } from './retry-terminal-recovery';
import { getOutgoingMessageIntent, migrateRetryRequestRecords } from '../local/store/reliability';
import {
  checkNewSendTimestamp,
  SEND_TIMESTAMP_ORIGIN,
  type SendTimestampOrigin,
  type SendTimestampOriginKind,
} from './send-timestamp';
import { deliveredEnvelopeFingerprint } from '../local/store/received-content';
import { RECEIVE_WORK_DEFAULT_LIMIT, sizedReceiveWork } from '../local/store/receive-work';
import {
  awaitReceiveCompletion,
  blockReceiveWork,
  completeReceiveWork,
  denyReceiveWork,
  ReceiveQueue,
} from './receive-queue';
import { receiveExpiresAt } from './receive-expiry';
import { boundReceiveHooks } from './receive-hook-bound';
import { createReceiveCommit } from './receive-work-seed';
import * as RelaySubscriptionOps from './relay-subscription';
import { relayReceiptJoinOf } from './relay-receipt-join';
import { SignalProtocolClientState, SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
import {
  clientRelayFanOut,
  rethrowRelayWorkStopped,
  RelayWorkStopped,
  type RelayWork,
} from './relay-work';
import { StaleSessionRefreshError } from './relay-device-refusal';
import type { BoundedFanOut } from '../utils/bounded-fan-out';
import { createKeyedLocks, withKeyedLock } from '../utils/keyed-lock';
import {
  deleteMediaAttachment,
  resolveMediaAttachment,
  type MediaAttachmentPointer,
} from '../media';
import { StorageBackedSignalProtocolClientMedia, type SignalProtocolClientMedia } from './media';

// Group state (Signal Private Group System)
import { GroupManager, decodeGroupTrustRoot } from '../internal/groups';
import type {
  DecryptedGroup,
  AccessControl,
  GroupMemberInput,
  GroupStateStore,
} from '../internal/groups';
import type { GroupId } from '../internal/groups/group-id';
import { SignalProtocolGroupStateStore } from '../internal/groups/sdk-store';
import { deriveAccessKey } from '../internal/protocol/sealed-sender/delivery-token';
import { SealedSenderContentType } from '../internal/protocol/sealed-sender/types';

export {};

/**
 * Module-level lock for storage initialization.
 * Prevents multiple concurrent DefaultSignalProtocolClient.create() calls from creating
 * duplicate storage adapters that compete for database locks.
 */
const storageLock = new AsyncLock({
  timeout: 30000, // 30 second timeout for storage initialization
  maxPending: 100, // Limit pending operations
});

/**
 * `decryptGroupMessage` calls for one group message run one at a time per
 * local store, from the read of its receive record to its completion, so
 * one content is given once.
 */
const groupMessageReceiveLocks = createKeyedLocks();

/** The reason of a `denied` receive outcome. */
function receiveDenialReason(error: Error): string {
  if (error instanceof GroupReceiveRefusedError) return error.reason;
  if (error instanceof EncryptionError) return error.code;
  return 'invalid';
}

/**
 * Type guard: DataMessage is a plain object (not string or Uint8Array).
 * TypeScript enforces correct content types at compile time. This routes at runtime.
 */
function isDataMessage(
  content: DataMessageInput | string | Uint8Array
): content is DataMessageInput {
  return (
    typeof content === 'object' &&
    content !== null &&
    !(content instanceof Uint8Array) &&
    !ArrayBuffer.isView(content)
  );
}

/** @internal Same client lifecycle with an owner-enforced existing identity. */
export function createClientWithRetainedIdentities(
  userId: string,
  config: SignalProtocolClientConfig,
  identities: RetainedIdentities,
): Promise<DefaultSignalProtocolClient> {
  if (config.protocolManager !== undefined) {
    throw new TypeError('Retained startup requires the SDK protocol manager.');
  }
  return createRetainedClient(userId, config, identities);
}
let createRetainedClient: (
  userId: string,
  config: SignalProtocolClientConfig,
  identities: RetainedIdentities,
) => Promise<DefaultSignalProtocolClient>;

/**
 * Modern Signal Protocol Client
 *
 * Provides a clean, testable, and flexible API for Signal Protocol operations.
 * Uses static factory pattern for type-safe async initialization:
 * - Guaranteed initialization via create() method
 * - Dependency injection support
 * - Configuration object pattern
 * - Clear error handling
 * - Type-safe API
 *
 * This client implements the SignalProtocolClient interface and wraps
 * DefaultSignalProtocolManager with additional high-level functionality.
 *
 * @category Primary API
 */
export class DefaultSignalProtocolClient implements SignalProtocolClient {
  static #retainedFactory = (createRetainedClient = (userId, config, identities) =>
    DefaultSignalProtocolClient.#createOwned(userId, config, identities));

  private readonly manager: SignalProtocolManager;
  private readonly _storage: SignalProtocolLocalStore;
  private readonly relay?: SignalProtocolRelayServer;
  private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore;
  private readonly config: SignalProtocolClientConfig;
  private readonly _userId: string;
  public readonly logger: Required<Logger>;
  private hooks: SignalProtocolClientHooks;
  /** The delivery status of the outgoing messages of this client. */
  private readonly deliveries: DeliveryStatusTracker;
  private readonly contentAdapter: SignalProtocolContentAdapter;

  // Multi-device support (Phase 2)
  public readonly deviceId: number; // 1 = primary, 2-5 = linked devices

  /**
   * Get user ID for this client instance
   * @see SignalProtocolClient.userId
   */
  public get userId(): string {
    return this._userId;
  }
  private readonly sesameManager: SesameManager; // Sesame protocol manager for multi-device support
  private readonly _address: ProtocolAddress; // Cached own address

  // Group messaging support (Sender Keys)
  private readonly senderKeyManager: SenderKeyManager;
  private readonly groupSenderKeys: GroupSenderKeyOperations;

  // Group state management
  private groupManager?: GroupManager;
  private groupSessionFor?: (authority: GroupAuthority) => {
    manager: GroupManager;
    endorsementManager?: GroupAuthority['endorsementManager'];
  };
  private groupStore?: GroupStateStore;
  /** Decides on received managed-group content. Set with a group store. */
  private groupReceiveEvaluator?: GroupReceiveEvaluator;
  /** The single fetcher that brings each group up to its claimed revision. */
  private groupFetcher?: GroupFetcher;
  /** The current membership that a retry resend of group content needs. */
  private readonly groupMembership: GroupMembershipChecker;
  /** The processor of the stored receive records. */
  private readonly receiveQueue: ReceiveQueue;

  // Cipher coordination (encrypts/decrypts, routes to appropriate cipher)
  private readonly cipher: SignalProtocolServiceCipher;

  // The relay request bound that every fan-out of this client shares
  private readonly fanOut: BoundedFanOut;

  /**
   * Durable media job facade backed by the configured Signal Protocol local store.
   *
   * Use this for background-safe attachment uploads, downloads, and cleanup
   * when the app provides media lifecycle callbacks in `config.media`.
   */
  public readonly media: SignalProtocolClientMedia;

  /**
   * Indicates the result of initial server sync during create().
   * 'synced' = successful, 'failed' = sync threw (offline mode), 'none' = no relay configured.
   */
  private _syncStatus: 'synced' | 'failed' | 'none' = 'none';
  get syncStatus(): 'synced' | 'failed' | 'none' {
    return this._syncStatus;
  }

  /** The validated content recovery policy, with its defaults applied. */
  private readonly contentRecoveryPolicy: ResolvedContentRecoveryPolicy;
  private readonly _contentRecoveryStatus: ContentRecoveryStatus;
  /** True after the client logged that a group send went out as `Default`, not `Resendable`. */
  private resendableDowngradeLogged = false;
  /** The resendable content that this client keeps, and its retention. */
  private readonly resendableContent: ResendableContent;

  /**
   * Whether this client keeps resendable content to answer retry requests.
   *
   * @see SignalProtocolClient.contentRecoveryStatus
   */
  get contentRecoveryStatus(): ContentRecoveryStatus {
    return this._contentRecoveryStatus;
  }

  private readonly stoppedRelayConnection: RelayConnectionState = {
    state: 'stopped',
    since: Date.now(),
  };

  /**
   * The connection state of the relay subscription. Reads `stopped` when no
   * relay is configured.
   *
   * @see SignalProtocolClient.relayConnectionState
   */
  get relayConnectionState(): RelayConnectionState {
    return this.relay?.relayConnectionState ?? this.stoppedRelayConnection;
  }

  /**
   * Subscribe to relay connection transitions. Without a relay, the listener
   * never runs.
   *
   * @see SignalProtocolClient.subscribeRelayConnectionState
   */
  public subscribeRelayConnectionState(
    listener: (state: RelayConnectionState) => void
  ): Unsubscribe {
    return this.relay?.subscribeRelayConnectionState(listener) ?? (() => undefined);
  }

  private relayUnsubscribe?: Unsubscribe;

  /**
   * Cached sender certificate for sealed sender.
   * Lazily fetched and refreshed one hour before its signed expiration.
   */
  private cachedSenderCertificate: string | null = null;
  private cachedCertificateExpiry: number = 0;

  /**
   * Centralized state management for retry/rotation tracking
   * @see SignalProtocolClientState for state details
   */
  private readonly state = new SignalProtocolClientState();

  /**
   * The delivery receipt sends in progress, from a batch timer, the batch
   * bound, stopRelaySubscription(), or stop(): the relay work item of each
   * send, and the promise that settles when the send finishes. While stop()
   * holds the batches, only stop() starts a send. stop() waits until its
   * receipt deadline for the sends that are in progress when it starts,
   * except a send that an earlier stop() stopped, and for the sends that it
   * starts. It does not stop them before then.
   */
  private readonly deliveryReceiptSends = new Map<RelayWork, Promise<void>>();

  /**
   * Posts the stored retry requests at their next attempt times, ends them
   * at their deadlines, and calls `onRetryTerminal`. create() and
   * startRelaySubscription() start it when a relay is configured, and stop()
   * stops it. Each pass is relay work, so its hooks run through that work.
   */
  private readonly retryRequests = new RetryRequestScheduler(this.state.relayWork, (work) => {
    const relay = this.relay;
    const context = { ...this.relayWorkContext(work), stopSignal: work.stopSignal };
    return {
      storage: this._storage,
      logger: this.logger,
      hooks: work.wrapHooks(this.hooks),
      local: { userId: this.userId, deviceId: this.deviceId },
      send: relay
        ? retryRequestPost(
            (recipientUserId, recipientDeviceId, payloadBase64) =>
              this.cipher.sealRetryRequest(recipientUserId, recipientDeviceId, payloadBase64),
            relay,
            (envelope) => relay.send(envelope),
            (recipientUserId, recipientDeviceId) =>
              this.cipher.recipientRegistrationId(recipientUserId, recipientDeviceId),
            (recipientUserId, recipientDeviceId) =>
              this.refreshRefusedSession(context, recipientUserId, recipientDeviceId)
          )
        : undefined,
      reset: this.retryTerminalReset(context),
    };
  });

  /**
   * Runs the pending resend jobs that an answer to a retry request did not
   * finish. It starts with the retry request scheduler and at each relay
   * transition to connected, and stop() stops it. Each pass is relay work,
   * so its hooks run through that work.
   */
  private readonly resendJobs = new ResendJobDriver(this.state.relayWork, (work) => {
    const ctx = this.relayWorkContext(work) as RetryOps.RetryContext;
    return {
      storage: this._storage,
      logger: this.logger,
      run: (jobId) =>
        RetryOps.runResendJob(
          ctx,
          jobId,
          this.retryResponseState,
          this.retryCallbacks(work.stopSignal, ctx)
        ),
    };
  });

  /** Ends the subscription of the resend job driver to relay connection states. */
  private resendJobsOnConnect: (() => void) | undefined;

  /**
   * The stop() in progress. It is set before a step of stop() runs, so a
   * stop() call that overlaps it, also from a step, waits for it, and a
   * subscription start is refused.
   */
  private stopping?: Promise<void>;

  /**
   * Get retry rate limiting state for retry operations
   */
  private get rateLimitState(): RetryOps.RetryRateLimitState {
    return this.state.getRateLimitState();
  }

  // Constants are now imported from state.ts for single source of truth
  // See SIGNAL_PROTOCOL_CLIENT_CONSTANTS for timing and retry configuration

  /**
   * Private constructor - use DefaultSignalProtocolClient.create() to instantiate
   *
   * @param userId - User identifier
   * @param deviceId - Device identifier (1 = primary, 2-5 = linked devices)
   * @param config - Configuration for the client
   */
  private constructor(userId: string, deviceId: number, config: SignalProtocolClientConfig) {
    if (
      config.deliveryReceipts !== undefined &&
      !['auto', 'always', 'off'].includes(config.deliveryReceipts)
    ) {
      throw new Error("deliveryReceipts must be 'auto', 'always', or 'off'");
    }
    const maxSkip = config.ratchetConfig?.maxSkip;
    if (maxSkip !== undefined && (!Number.isSafeInteger(maxSkip) || maxSkip <= 0)) {
      throw new Error('ratchetConfig.maxSkip must be a positive integer.');
    }
    this._userId = userId;
    this.deviceId = deviceId;
    this.config = config;
    this.logger = resolveSignalProtocolLogger(config.logger);
    for (const name of Object.keys(config.hooks ?? {})) assertHookName(name);
    this.hooks = config.hooks || {};
    this.contentAdapter = config.contentAdapter ?? createDefaultSignalProtocolContentAdapter();

    // Dependency injection: use the provided relay adapter when configured.
    this.relay = config.relay;
    // A relay adapter that sends relay requests itself shares its bound.
    this.fanOut = clientRelayFanOut(config.relay);

    // Dependency injection: use the remote object store for encrypted attachments.
    this.remoteObjectStore = config.remoteObjectStore;

    // Dependency injection: Storage is always provided by create() callers.
    if (!config.storage) {
      throw new Error('Storage must be provided by DefaultSignalProtocolClient.create() callers');
    }
    this._storage = config.storage;
    // The store declares its protection. The policy decides from it whether
    // the client keeps resendable content.
    this.contentRecoveryPolicy = resolveContentRecoveryPolicy(config.protocol?.contentRecovery);
    // Each queue pass runs as relay work, so its hooks call the app through
    // that work and a stop ends it. Each hook runs under the receive hook bound.
    this.receiveQueue = new ReceiveQueue(
      this.state.relayWork,
      resolveReceiveQueuePolicy(config.protocol?.receiveQueue),
      (work) => {
        const ctx = this.receivePassContext(work);
        return {
          ctx: {
            ...ctx,
            cipher: this.cipher,
            receiveQueue: this.receiveQueue,
            stopSignal: work.stopSignal,
          },
          state: this.relaySubscriptionState,
          callbacks: this.relaySubscriptionCallbacks(ctx, work.stopSignal),
        };
      },
      () => this.cleanupStaleDeviceRecords()
    );
    this._contentRecoveryStatus = decideContentRecovery(
      readLocalStoreProtection(this._storage),
      this.contentRecoveryPolicy,
      config.groups?.resolveAciBytesByUserIds
        ? 'managed'
        : this.contentRecoveryPolicy.isCurrentMember
          ? 'hook'
          : 'none'
    );
    this.resendableContent = new ResendableContent(
      this._storage,
      this.contentRecoveryPolicy.retentionMs
    );
    this.deliveries = new DeliveryStatusTracker(this._storage);
    (
      this._storage as SignalProtocolLocalStore & {
        setLogger?: (logger?: Logger) => void;
      }
    ).setLogger?.(this.logger);

    this.media = new StorageBackedSignalProtocolClientMedia({
      storage: this._storage,
      remoteObjectStore: this.remoteObjectStore,
      config: config.media,
    });

    // Dependency injection: Use provided protocol manager or create new one with our storage,
    // protocol strategy, and skip limit. A provided manager keeps its own skip limit.
    this.manager =
      config.protocolManager ??
      new DefaultSignalProtocolManager(
        this._storage,
        config.protocolStrategy,
        this.logger,
        config.ratchetConfig?.maxSkip
      );

    // Validate manager was created successfully before initializing Sesame
    if (!this.manager) {
      throw new EncryptionError(
        'Protocol manager must be initialized before Sesame manager',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    // Initialize Sesame manager for multi-device support
    this.sesameManager = new DefaultSesameManager(
      this._storage,
      {}, // Use default Sesame config
      this.manager,
      undefined,
      this.logger
    );

    // Wire up MessageRecord storage for retry request support (SESAME spec §6.2).
    // A refused content recovery keeps no record, so a pairwise retry request
    // resets the session with no content.
    // A record keeps no sender key distribution, so no chain key rests in it.
    if (this._contentRecoveryStatus.enabled) {
      this.sesameManager.setMessageRecordStore(this._storage, (plaintext) =>
        this.contentAdapter.withoutSenderKeyDistribution(plaintext)
      );
    }

    // Initialize Sender Key manager for group messaging
    this.senderKeyManager = new SenderKeyManager(this._storage, config?.senderKeys, this.logger);
    this.groupSenderKeys = new GroupSenderKeyOperations(this._storage, userId, deviceId);

    // Initialize the group manager if configured
    if (config?.groups) {
      const groupConfig = config.groups;
      // Each client write to a group record reports a changed init status.
      this.groupStore = observeGroupInitStatus(
        config.groups.store ?? new SignalProtocolGroupStateStore(this._storage),
        {
          isObserved: () => typeof this.hooks.onGroupInitStatus === 'function',
          report: (groupId, status) =>
            callHook(this.hooks, 'onGroupInitStatus', createGroupId(groupId), status),
          logger: this.logger,
        }
      );
      const sessions = new WeakMap<GroupAuthority, { manager: GroupManager; endorsementManager?: GroupAuthority['endorsementManager'] }>();
      this.groupSessionFor = (authority) => {
        const cached = sessions.get(authority);
        if (cached) return cached;
        const capability = this.relay?.groupServer;
        const server = groupConfig.server ?? capability?.server;
        const issueCredential =
          groupConfig.issueCredential ??
          (capability ? () => capability.issueAuthCredential(this._userId, authority.authorityKeyId) : undefined);
        const issueProfileKeyCredential =
          groupConfig.issueProfileKeyCredential ??
          (capability
            ? async (request: Uint8Array) => {
                const accessKey = await deriveAccessKey(groupConfig.profileKey);
                await capability.setUnidentifiedAccessKey(this._userId, accessKey);
                return capability.issueProfileKeyCredential(this._userId, request, authority.authorityKeyId);
              }
            : undefined);

        if (!server || !issueCredential || !issueProfileKeyCredential) {
          const missing = [
            !server ? 'server' : undefined,
            !issueCredential ? 'issueCredential' : undefined,
            !issueProfileKeyCredential ? 'issueProfileKeyCredential' : undefined,
          ].filter((value): value is string => value !== undefined);
          throw new Error(
            `Groups require the relay.groupServer capability or explicit overrides; missing: ${missing.join(', ')}`
          );
        }
        if (!config.aci) {
          throw new Error('Groups require the client identity ACI; set identity.aci');
        }

        const trustRoot = decodeGroupTrustRoot(authority.trustRoot);
        const endorsementManager = authority.endorsementManager;
        endorsementManager?.assertEndorsementRootPublicKey(trustRoot.endorsementRootPublicKey);

        const manager = new GroupManager({
          store: this.groupStore!,
          authorityKeyId: authority.authorityKeyId,
          server,
          issueCredential,
          credentialPublicKey: trustRoot.credentialPublicKey,
          serverSigningPublicKey: trustRoot.serverSigningPublicKey,
          allowUnauthenticatedGroupHistory: groupConfig.allowUnauthenticatedGroupHistory,
          onConfigurationWarning: groupConfig.onConfigurationWarning,
          aci: config.aci,
          pni: config.pni,
          issueProfileKeyCredential,
          profileKeyCredentialPublicKey: trustRoot.profileKeyCredentialPublicKey,
          profileKey: groupConfig.profileKey,
          onSenderKeyRotation: async (groupId) => {
            await this.groupSenderKeys.run(groupId, (rawGroupId) =>
              GroupOps.rotateGroupSenderKey(
                this.ctx,
                this.senderKeyManager,
                rawGroupId,
                this.config.onGroupSenderKeyRotated
              )
            );
          },
          onEndorsementsInvalidated: endorsementManager
            ? async (groupId) => {
                await endorsementManager.clearGroupEndorsements(groupId);
              }
            : undefined,
        });
        const session = { manager, endorsementManager };
        sessions.set(authority, session);
        return session;
      };
      this.groupManager = this.groupSessionFor(config.groups).manager;
    }

    // Initialize cipher for encrypt/decrypt coordination
    this.cipher = new SignalProtocolServiceCipher(
      this._userId,
      deviceId,
      this.sesameManager,
      this.senderKeyManager,
      this._storage,
      this.relay,
      this.remoteObjectStore,
      this.contentAdapter,
      this.logger,
      this.fanOut
    );
    if (this.groupManager) {
      this.cipher.setGroupSendBarrierChecker((groupId) =>
        this.groupManager!.assertGroupSendAllowed(groupId)
      );
    }

    // The client applies each Relay delivery receipt of its relay.
    if (this.relay) {
      relayReceiptIntakeOf(this.relay)?.subscribe((receipt) => this.receiveRelayReceipt(receipt));
    }

    // Set up auto-session establishment and stale-session refresh.
    // This enables lazy session creation when sending to users without established sessions
    const sessions = this.sendSessionCallbacks(() => this.ctx);
    if (sessions) this.cipher.setSessionCallbacks(sessions);
    // A sync payload has no send result, so the cipher reports its error.
    this.cipher.setRelayProtocolErrorReporter((error) =>
      callHook(this.hooks, 'onRelayProtocolError', error)
    );

    if (config?.sealedSender) {
      this.cipher.setSealedSenderDeliveryMode(config.sealedSender.deliveryMode ?? 'preferred');
      if (config.sealedSender.onIdentifiedFallback) {
        this.cipher.setSealedSenderIdentifiedFallback(config.sealedSender.onIdentifiedFallback);
      }
    }

    // Set up sealed sender provider if configured
    if (this.isSealedSenderEnabled) {
      this.cipher.setSealedSenderProvider(async () => {
        const certBase64 = await this.fetchSenderCertificate();
        const identityKeyPair = await this._storage.getIdentityKey();
        if (!identityKeyPair) {
          throw new EncryptionError(
            'No identity key pair for sealed sender',
            EncryptionErrorCode.INITIALIZATION_FAILED
          );
        }
        return {
          senderCertificateBase64: certBase64,
          senderIdentityPrivate: base64ToBytes(identityKeyPair.dhKey.privateKey),
          senderIdentityPublic: base64ToBytes(identityKeyPair.dhKey.publicKey),
          config: this.config.sealedSender!,
        };
      });
    }

    if (config?.sealedSender?.contactStateStore) {
      this.cipher.setContactProfileStateStore(config.sealedSender.contactStateStore);
    }

    // Set up endorsement manager if configured
    if (config?.groups?.endorsementManager) {
      this.cipher.setEndorsementManager(config.groups.endorsementManager,
        config.groups.resolveAuthority ? async () => (await this.resolveGroupSession()).endorsementManager : undefined);
    }

    // Set up group secret params provider. Derives params from master key in store
    if (this.groupStore) {
      const store = this.groupStore;
      const isGroupBlocked = config.groups?.isGroupBlocked;
      // The fetcher's sync keeps the group server's denial errors, so it
      // calls the manager directly. syncGroup() wraps them for the caller.
      const fetcher = new GroupFetcher({
        store,
        sync: async (groupId) => (await this.groups).syncGroup(createGroupId(groupId)),
        ...(isGroupBlocked && {
          isBlocked: (groupId: string) => isGroupBlocked(createGroupId(groupId)),
        }),
        applyChange: async (groupId, revision, change) =>
          (await this.groups).applyCarriedGroupChange(groupId, revision, change),
        // The receive queue owns the content that waits on a group.
        hasBlockedContent: async (groupId) =>
          (await this._storage.receiveWorkUsage({ groupId })).items > 0,
        onFetched: (groupId) => this.receiveQueue.wake(groupId),
        runInBackground: (pass) => this.state.relayWork.run(() => pass()),
        logger: this.logger,
      });
      this.groupFetcher = fetcher;
      this.groupReceiveEvaluator = createGroupReceiveEvaluator({
        store,
        fetcher,
        ownUserId: userId,
        localAci: config.aci?.uuid,
        resolveAcis: config.groups?.resolveAciBytesByUserIds,
        ...(isGroupBlocked && { isGroupBlocked }),
      });
      this.cipher.setGroupReceiveEvaluator(this.groupReceiveEvaluator);
      this.cipher.setGroupSecretParamsProvider(async (groupId: string) => {
        const masterKey = await store.getMasterKey(groupId);
        if (!masterKey) return null;
        return deriveGroupSecretParams(masterKey);
      });
      // Each send to a managed group carries its master key and the
      // revision of the verified state, as Signal's GroupContextV2.
      this.cipher.setGroupContextProvider(async (groupId: string) => {
        const masterKey = await store.getMasterKey(groupId);
        if (!masterKey) return null;
        const state = await store.getGroupState(groupId);
        return { masterKey, revision: state?.revision ?? 0 };
      });
    }
    this.groupMembership = createGroupMembershipChecker(
      this.groupStore,
      config.groups?.resolveAciBytesByUserIds,
      this.contentRecoveryPolicy.isCurrentMember,
      this.groupFetcher
    );

    // Set up endorsement refresher for pre-send V2 sealed sender refresh.
    // Fetches fresh endorsements from server when cache is empty, expiring, or
    // missing members.
    if (
      config?.groups?.endorsementManager &&
      this.groupStore &&
      this.relay?.refreshGroupSendEndorsements &&
      this.groupManager
    ) {
      const groupConfig = config.groups;
      const groupStore = this.groupStore;
      const relay = this.relay;
      const selfUserId = this._userId;

      this.cipher.setEndorsementRefresher(async (groupId: string, memberUserIds: string[]) => {
        const { manager: groupManager, endorsementManager } = await this.resolveGroupSession();
        if (!endorsementManager) return false;
        // 1. Build ZK authorization (credential presentation + group public params)
        const authorization = await groupManager.getAuthorization(groupId);

        // 2. Get group secret params for endorsement processing
        const masterKey = await groupStore.getMasterKey(groupId);
        if (!masterKey) return false;
        const secretParams = deriveGroupSecretParams(masterKey);

        // 3. Derive the protocol identifier, not the display identifier's UTF-8 bytes.
        const groupIdBytes = getGroupPublicParams(secretParams).groupId;

        // 4. Fetch fresh endorsements from server
        const { endorsements } = await relay.refreshGroupSendEndorsements!(
          groupIdBytes,
          authorization
        );

        // 5. Get cached group state for member ordering (server order)
        const state = await groupStore.getGroupState(groupId);
        if (!state || state.members.length === 0) return false;

        // 6. Build ACI→userId mapping from known members + self.
        //    Endorsements are issued in group-state member order, so we must
        //    build parallel arrays matching that order.
        const allUserIds = [...memberUserIds, selfUserId];
        const aciHexToUserId = new Map<string, string>();
        const resolvedAciBytes = groupConfig.resolveAciBytesByUserIds
          ? await groupConfig.resolveAciBytesByUserIds(allUserIds)
          : new Map<string, Uint8Array>();
        for (const [userId, aciBytes] of resolvedAciBytes.entries()) {
          const hex = Array.from(aciBytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
          aciHexToUserId.set(hex, userId);
        }

        // 7. Build parallel arrays in group-state member order
        const memberServiceIds: import('../internal/protocol/zk/groups/uid-struct').ServiceId[] =
          [];
        const orderedUserIds: string[] = [];
        for (const member of state.members) {
          const hex = Array.from(member.aciBytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
          const userId = aciHexToUserId.get(hex);
          if (!userId) continue; // Unknown member. Skip
          memberServiceIds.push({
            kind: SERVICE_ID_ACI,
            uuid: member.aciBytes,
          });
          orderedUserIds.push(userId);
        }

        // 8. Process and cache endorsements
        await endorsementManager.processAndCacheEndorsements(
          groupId,
          endorsements,
          memberServiceIds,
          orderedUserIds,
          selfUserId,
          secretParams
        );

        return true;
      });
    }

    // NOTE: hooks are initialized in constructor (this.hooks = config?.hooks || {})

    if (config?.enableDebugLogging) {
      this.logger.debug('DefaultSignalProtocolClient created', {
        category: 'E2EE',
        data: { userId, deviceId, config: this.sanitizeConfig(config) },
      });
    }

    // Cache own address (userId and deviceId are immutable)
    this._address = ProtocolAddress.create(this.userId, this.deviceId);
  }

  /**
   * Get client context for operation modules
   */
  private get ctx(): SignalProtocolClientContext {
    return {
      userId: this.userId,
      deviceId: this.deviceId,
      manager: this.manager,
      storage: this._storage,
      relay: this.relay,
      remoteObjectStore: this.remoteObjectStore,
      config: this.config,
      logger: this.logger,
      hooks: this.hooks,
      sesameManager: this.sesameManager,
      contentAdapter: this.contentAdapter,
      profileKeys: profileKeyExchange(this),
      deliveries: this.deliveries,
      resendableContent: this.resendableContent,
      scheduleRetryRequest: (at) => this.retryRequests.schedule(at),
      retryTerminalReset: (context) => this.retryTerminalReset(context),
      recipientRegistrationId: (recipientUserId, recipientDeviceId) =>
        this.cipher.recipientRegistrationId(recipientUserId, recipientDeviceId),
      refreshStaleSession: (context, recipientUserId, recipientDeviceId) =>
        this.refreshRefusedSession(context, recipientUserId, recipientDeviceId),
      sealReceipt: (recipientUserId, recipientDeviceId, ciphertextBase64) =>
        this.cipher.sealReceipt(recipientUserId, recipientDeviceId, ciphertextBase64),
      sealRetryRequest: (recipientUserId, recipientDeviceId, payloadBase64) =>
        this.cipher.sealRetryRequest(recipientUserId, recipientDeviceId, payloadBase64),
    };
  }

  /**
   * Apply one Relay delivery receipt, then announce its deliveries. A
   * receipt whose write or announcement does not complete throws, so the
   * Relay replays it: after a stop(), and after an error from the
   * `onDelivered` hook. The replay announces each delivery whose hook did not
   * return.
   */
  private async receiveRelayReceipt(receipt: RelayDeliveryReceipt): Promise<void> {
    let announced = false;
    await this.state.relayWork.run(async (work) => {
      work.proceed();
      const events = await this.deliveries.applyRelayReceipt(receipt);
      await this.deliveries.announce(work.wrapHooks(this.hooks), events);
      announced = true;
    });
    if (!announced) throw new RelayWorkStopped();
  }

  /**
   * Announce the deliveries that waited for a send of this client message ID
   * to resolve. A delivery whose hook throws or stops stays unannounced, and
   * the next receipt for the message announces it again.
   */
  private releaseDeliveries(clientMessageId: string): void {
    void this.state.relayWork
      .run(async (work) => {
        work.proceed();
        const events = await this.deliveries.release(clientMessageId);
        await this.deliveries.announce(work.wrapHooks(this.hooks), events);
      })
      .catch((error: unknown) => {
        this.logger.warn('Failed to announce deliveries', {
          category: 'E2EE',
          data: { clientMessageId, error: (error as Error).message },
        });
      });
  }

  /**
   * Whether the client enables and configures sealed sender.
   */
  get isSealedSenderEnabled(): boolean {
    const ss = this.config.sealedSender;
    return !!(ss && ss.deliveryMode !== 'disabled' && ss.trustRoots.length > 0);
  }

  /**
   * Fetch (or return cached) sender certificate for sealed sender.
   *
   * Uses the configured certificateProvider or relay.fetchSenderCertificate().
   * Validates the fetched certificate and caches it until one hour before its
   * signed expiration.
   *
   * @returns Base64-encoded serialized SenderCertificate
   * @throws if no certificate provider is available
   */
  async fetchSenderCertificate(): Promise<string> {
    const now = Date.now();

    if (this.cachedSenderCertificate && now < this.cachedCertificateExpiry) {
      return this.cachedSenderCertificate;
    }

    const sealedSender = this.config.sealedSender;
    if (!sealedSender || sealedSender.trustRoots.length === 0) {
      throw new EncryptionError(
        'Sender certificate trust is not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    // Fetch from configured provider or relay
    let certBase64: string;
    if (sealedSender.certificateProvider) {
      certBase64 = await sealedSender.certificateProvider();
    } else if (this.relay?.fetchSenderCertificate) {
      certBase64 = await this.relay.fetchSenderCertificate(this.deviceId);
    } else {
      throw new EncryptionError(
        'No sender certificate provider configured. Set sealedSender.certificateProvider or use a relay that supports fetchSenderCertificate.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    let certificate: ReturnType<typeof deserializeSenderCertificate>;
    try {
      certificate = deserializeSenderCertificate(base64ToBytes(certBase64 as Base64));
      await validateSenderCertificate(
        certificate,
        sealedSender.trustRoots.map((root) => bytesToBase64(root) as Base64),
        now,
        {
          expectedRelayScopeId: bytesToBase64(sealedSender.relayScopeId) as Base64,
          revokedIssuerKeyIds: sealedSender.revokedIssuerKeyIds,
        }
      );
      const identity = await this._storage.getIdentityKey();
      if (
        !identity ||
        certificate.senderUuid !== this.userId ||
        certificate.senderDeviceId !== this.deviceId ||
        !constantTimeEqual(
          base64ToBytes(certificate.senderIdentityKey),
          base64ToBytes(identity.dhKey.publicKey)
        )
      ) {
        throw new Error('certificate binding mismatch');
      }
    } catch {
      throw new EncryptionError(
        'Fetched sender certificate failed client binding validation',
        EncryptionErrorCode.INVALID_CIPHERTEXT
      );
    }

    const refreshAt = certificate.expires - SEALED_SENDER_CERTIFICATE_MARGIN_MS;
    if (refreshAt > now) {
      this.cachedSenderCertificate = certBase64;
      this.cachedCertificateExpiry = refreshAt;
    } else {
      this.cachedSenderCertificate = null;
      this.cachedCertificateExpiry = 0;
    }

    return certBase64;
  }

  /**
   * Get GroupManager, throwing if not configured.
   */
  private async resolveGroupSession() {
    if (!this.groupSessionFor || !this.config.groups) {
      throw new EncryptionError(
        'Groups not configured. Provide groups config to DefaultSignalProtocolClient.create().',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    const authority = this.config.groups.resolveAuthority
      ? await this.config.groups.resolveAuthority()
      : this.config.groups;
    return this.groupSessionFor(authority);
  }

  private get groups(): Promise<GroupManager> {
    return this.resolveGroupSession().then((session) => session.manager);
  }

  /**
   * Get retry configuration for retry operations
   */
  private get retryConfig(): RetryOps.RetryConfig {
    return {
      keyRotationDebounceMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.KEY_ROTATION_DEBOUNCE_MS,
    };
  }

  /**
   * Get retry response state for retry operations
   */
  private get retryResponseState(): RetryOps.RetryResponseState {
    return this.state.getRetryResponseState();
  }

  /**
   * Get retry callbacks for retry operations. Session changes use the given
   * context, so their hooks run through its relay work. A resend goes only to
   * the device that asked, and waits for the recipient's lock only until the
   * stop signal aborts.
   */
  private retryCallbacks(
    stopSignal: AbortSignal | undefined,
    ctx: SignalProtocolClientContext
  ): RetryOps.RetryCallbacks {
    return {
      archiveSession: (address) => SessionOps.archiveSession(ctx, address),
      establishSession: (address, bundle) =>
        SessionOps.establishSession(ctx, this.sesameManager, address, bundle),
      resend: (userId, deviceId, content, options) =>
        this.cipher.resendToDevice(userId, deviceId, content, options, stopSignal),
      forcePreKeyRotation: () => this.regeneratePreKeysWithFreshIds(),
      groupMembership: this.groupMembership,
      findSentGroupId: (userId, clientTimestamp) =>
        this.cipher.findSentGroupId(userId, clientTimestamp),
      currentGroupDistribution: (groupId) =>
        this.cipher.currentGroupDistribution(groupId, stopSignal),
      invalidateSenderKeyHandoff: (groupId, device) =>
        this.groupSenderKeys.run(
          groupId,
          (rawGroupId) => this.cipher.invalidateSenderKeyHandoff(rawGroupId, device),
          stopSignal
        ),
    };
  }

  /**
   * Get relay subscription state (passed to relay-subscription module)
   */
  private get relaySubscriptionState(): RelaySubscriptionOps.RelaySubscriptionState {
    return this.state.getRelaySubscriptionState();
  }

  /**
   * Get relay subscription callbacks (delegate back to DefaultSignalProtocolClient methods).
   * Receipts, typing indicators and retry requests use the given context, so
   * their hooks run through its relay work. Each receipt send is relay work of
   * its own. A retry request runs in the current work, so a stop of that work
   * reaches the receive route, and the route keeps the request envelope.
   */
  private relaySubscriptionCallbacks(
    ctx: SignalProtocolClientContext,
    stopSignal?: AbortSignal
  ): RelaySubscriptionOps.RelaySubscriptionCallbacks {
    return {
      forcePreKeyRotation: () => this.regeneratePreKeysWithFreshIds(),
      handleDeliveryReceipt: (envelope, receipt) =>
        this.handleDeliveryReceipt(envelope, receipt, ctx),
      handleTypingIndicator: (envelope, typing) =>
        this.handleTypingIndicator(envelope, typing, ctx),
      sendDeliveryReceipt: (userId, timestamps) => this.sendDeliveryReceiptAsRelayWork(userId, timestamps),
      handleRetryRequest: (request, retry) =>
        RetryOps.handleRetryRequestAndResend(
          ctx as RetryOps.RetryContext,
          request,
          this.retryResponseState,
          this.retryCallbacks(stopSignal, ctx),
          this.retryConfig,
          retry
        ),
    };
  }

  /**
   * Send one delivery receipt batch as relay work of its own. The context
   * carries the stop signal of the tracker, which also aborts at a stop
   * after the work ends, so a retry timer of the send sees that stop. The
   * send is in deliveryReceiptSends while it runs.
   *
   * @throws RelayWorkStopped when a stop ended the send before it finished,
   *   so the receive queue keeps the receipt and sends it after the next
   *   start
   */
  private async sendDeliveryReceiptAsRelayWork(
    userId: string,
    timestamps: number[]
  ): Promise<void> {
    let sent = false;
    await this.state.relayWork.run(async (work) => {
      const send = this.sendDeliveryReceipt(userId, timestamps, {
        ...this.relayWorkContext(work),
        stopSignal: this.state.relayWork.stopSignal,
      });
      this.deliveryReceiptSends.set(work, send);
      try {
        await send;
        sent = true;
      } finally {
        this.deliveryReceiptSends.delete(work);
      }
    });
    if (!sent) throw new RelayWorkStopped();
  }

  /**
   * Start the send of every batched delivery receipt, once each. The batches
   * leave the accumulator, so no batch timer sends them again. The returned
   * promises settle when the sends finish. They never reject.
   */
  private flushPendingDeliveryReceipts(): Promise<void>[] {
    return RelaySubscriptionOps.flushPendingReceipts(
      this.relaySubscriptionState.receiptAccumulator,
      (userId, timestamps) => this.sendDeliveryReceiptAsRelayWork(userId, timestamps),
      this.logger
    );
  }

  /**
   * Wait for the receipt sends that stop() waits for, with their app hooks,
   * for no more than the given time.
   */
  private async waitForStopReceiptSends(sends: Promise<void>[], ms: number): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const bound = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, Math.max(0, ms));
    });
    try {
      await Promise.race([Promise.allSettled(sends), bound]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * The session reset steps of a retry request that ended as
   * `expired-content`. Their session hooks run through the given context,
   * and its stop signal stops their lock waits and relay requests. There are
   * none without a relay.
   */
  private retryTerminalReset(
    context: SignalProtocolClientContext
  ): RetryTerminalResetSteps | undefined {
    const relay = this.relay;
    if (!relay) return undefined;
    const { stopSignal } = context;
    return {
      archiveSession: ({ userId, deviceId }) =>
        this.cipher.archiveDeviceSession(userId, deviceId, stopSignal),
      // No stop signal: a stop must not split the archive from the invalidation.
      invalidateAccountSenderKeyHandoffs: async (userId, groupId) => {
        if (groupId === undefined) {
          await this.cipher.invalidateAccountSenderKeyHandoffs(userId);
          return false;
        }
        return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
          await this.cipher.invalidateAccountSenderKeyHandoffs(userId);
          const current = await this.senderKeyManager.getCurrentSenderKeyDistribution(
            rawGroupId,
            this.userId,
            this.deviceId
          );
          return current !== null;
        });
      },
      sendNullMessage: async ({ userId, deviceId }) => {
        const address = ProtocolAddress.create(userId, deviceId);
        if (!(await SessionOps.hasSession(context, address))) {
          const bundle = await this.fanOut.request(
            () => relay.fetchPreKeyBundle(userId, deviceId),
            stopSignal
          );
          if (!bundle) throw new Error('No prekey bundle for the device of a session reset');
          await SessionOps.establishSession(context, this.sesameManager, address, bundle);
        }
        await this.cipher.resendToDevice(
          userId,
          deviceId,
          this.contentAdapter.serializeNullMessage(),
          { timestamp: Date.now(), contentHint: ContentHint.Implicit },
          stopSignal
        );
      },
    };
  }

  /**
   * Refresh the session with a device that the Relay refused as stale, for a
   * receipt or a retry request. It fetches a fresh bundle first, then starts
   * a new session from the bundle. The session start archives the stale
   * session and promotes the new one in one record write. After a successful
   * start, the onSessionArchived hook runs for the device. Resolves to true
   * when the new session is ready. Resolves to false without a relay, and
   * when the Relay has no bundle of the device: the session is then
   * archived. Rejects with StaleSessionRefreshError when the fetch or the new
   * session fails. A failure before the session record write keeps the
   * stale session, so the next post is refused again and refreshes again. A
   * failure after that write, in the SESAME registration, leaves the new
   * session, and the next post uses it.
   */
  private async refreshRefusedSession(
    context: SignalProtocolClientContext,
    recipientUserId: string,
    recipientDeviceId: number
  ): Promise<boolean> {
    const relay = this.relay;
    if (!relay) return false;
    const address = ProtocolAddress.create(recipientUserId, recipientDeviceId);
    try {
      const freshBundle = await this.fanOut.request(
        () => relay.fetchPreKeyBundle(recipientUserId, recipientDeviceId),
        context.stopSignal
      );
      if (!freshBundle) {
        // Per SESAME §3.2: the session is archived, not deleted, to decrypt
        // delayed messages. No bundle is terminal for the post.
        await SessionOps.archiveSession(context, address);
        this.logger.warn('No prekey bundle available for stale session refresh', {
          category: 'E2EE',
          data: { recipientUserId, recipientDeviceId },
        });
        return false;
      }
      // The session start archives the stale session in the same record write
      // that stores the new one, so a start that fails before that write
      // keeps the stale session.
      // The hook runs only after the start succeeds, for the session that the
      // write archived.
      const staleSession = (await context.storage.getSessionRecord(address))?.currentSession;
      await SessionOps.establishSession(context, this.sesameManager, address, freshBundle);
      if (staleSession) {
        await callHook(context.hooks, 'onSessionArchived', ProtocolAddress.toString(address));
      }
      this.logger.info('Refreshed stale session with fresh bundle', {
        category: 'E2EE',
        data: { recipientUserId, recipientDeviceId, newRegistrationId: freshBundle.registrationId },
      });
      return true;
    } catch (error) {
      rethrowRelayWorkStopped(error);
      this.logger.warn('Failed to refresh stale session, the post retries', {
        category: 'E2EE',
        data: { recipientUserId, recipientDeviceId, error: (error as Error).message },
      });
      throw new StaleSessionRefreshError(recipientUserId, recipientDeviceId, error);
    }
  }

  /** Client context whose hooks call the app through the given relay work. */
  private relayWorkContext(work: RelayWork): SignalProtocolClientContext {
    return { ...this.ctx, hooks: work.wrapHooks(this.hooks) };
  }

  /**
   * Client context of a receive queue pass. Its hooks run under the receive
   * hook bound, inside the given relay work, so the work stops waiting in the
   * app at a timeout.
   */
  private receivePassContext(work: RelayWork): SignalProtocolClientContext {
    const bound = boundReceiveHooks(
      this.hooks,
      this.receiveQueue.policy.receiveHookTimeoutMs,
      this.logger
    );
    return { ...this.ctx, hooks: work.wrapHooks(bound) };
  }

  /**
   * Session callbacks of a send. Their session hooks run through the given
   * context, so a send in relay work calls the app through that work. Session
   * setup sends its relay requests under the client's relay request bound, and
   * the stop signal ends it. There are none without a relay.
   */
  private sendSessionCallbacks(
    context: () => SignalProtocolClientContext,
    stopSignal?: AbortSignal
  ): SendSessionCallbacks | undefined {
    const relay = this.relay;
    if (!relay) return undefined;
    const establishSession = (address: ProtocolAddress, bundle: PreKeyBundle) =>
      SessionOps.establishSession(context(), this.sesameManager, address, bundle);
    return {
      establishSessions: (recipientUserId, listedDevices) =>
        establishMultiDeviceSessions(this, relay, recipientUserId, {
          establishSession,
          rethrowFatal: rethrowRelayWorkStopped,
          fanOut: this.fanOut,
          stopSignal,
          ...(listedDevices && { listedDevices }),
        }),
      // Stale-device recovery archives the old session, fetches a fresh bundle,
      // and establishes a replacement.
      // Per SESAME §3.2: session is archived (not deleted) to handle delayed messages
      refreshStaleSession: async (recipientUserId, recipientDeviceId) => {
        try {
          const address = ProtocolAddress.create(recipientUserId, recipientDeviceId);

          // 1. Archive the stale session (preserves for delayed message decryption)
          await SessionOps.archiveSession(context(), address);

          this.logger.debug('Archived stale session for refresh', {
            category: 'E2EE',
            data: { recipientUserId, recipientDeviceId },
          });

          // 2. Fetch fresh prekey bundle
          const freshBundle = await this.fanOut.request(
            () => relay.fetchPreKeyBundle(recipientUserId, recipientDeviceId),
            stopSignal
          );

          if (!freshBundle) {
            this.logger.warn('No prekey bundle available for stale session refresh', {
              category: 'E2EE',
              data: { recipientUserId, recipientDeviceId },
            });
            return false;
          }

          // 3. Establish new session with fresh keys
          await establishSession(address, freshBundle);

          this.logger.info('Refreshed stale session with fresh bundle', {
            category: 'E2EE',
            data: {
              recipientUserId,
              recipientDeviceId,
              newSignedPreKeyId: freshBundle.ecSignedPreKey.keyId,
              newRegistrationId: freshBundle.registrationId,
            },
          });

          return true;
        } catch (error) {
          rethrowRelayWorkStopped(error);
          this.logger.error('Failed to refresh stale session', {
            category: 'E2EE',
            data: {
              recipientUserId,
              recipientDeviceId,
              error: (error as Error).message,
            },
          });
          return false;
        }
      },
    };
  }

  /**
   * Run a task with hooks that the task queues and this method calls after
   * the task settles. A task that holds a group's Sender Key lock uses it, so
   * a hook can call a client method that takes the same lock.
   */
  private async withDeferredHooks<T>(
    context: SignalProtocolClientContext,
    task: (context: SignalProtocolClientContext) => Promise<T>
  ): Promise<T> {
    const deferred = deferHooks(context.hooks);
    let result: T;
    try {
      result = await task({ ...context, hooks: deferred.hooks });
    } catch (error) {
      await deferred.flush().catch(() => undefined);
      throw error;
    }
    await deferred.flush();
    return result;
  }

  /**
   * Get relay subscription config
   */
  private get relaySubscriptionConfig(): RelaySubscriptionOps.RelaySubscriptionConfig {
    return {
      keyRotationDebounceMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.KEY_ROTATION_DEBOUNCE_MS,
    };
  }

  /**
   * Create and initialize a new DefaultSignalProtocolClient instance.
   *
   * This low-level factory fully initializes the client before it returns
   * it. Most app code should prefer `createSignalProtocolClient()`, which
   * groups identity, adapters, and protocol policy in one object.
   *
   * If config provides `relay`, the client automatically uploads the
   * public prekey bundle needed for end-to-end encrypted messaging.
   *
   * @param userId - User identifier for this device/client
   * @param config - Optional configuration for the client
   * @returns Fully initialized DefaultSignalProtocolClient instance
   *
   * @example
   * ```typescript
   * import { DefaultSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
   *
   * // Local-only primary device.
   * const signal = await DefaultSignalProtocolClient.create('user-123', {
   *   storage,
   * });
   *
   * // Linked device; storage must already contain the account identity.
   * const signal = await DefaultSignalProtocolClient.create('user-123', {
   *   deviceId: 2,
   *   storage: linkedDeviceStorage
   * });
   *
   * // With an application-owned authenticated relay transport.
   * const relay = appRelayTransport;
   * const signal = await DefaultSignalProtocolClient.create('user-123', {
   *   storage,
   *   relay,
   *   onProgress: ({ stage, percent, message }) => {
   *     console.log(`${stage}: ${percent}% - ${message}`);
   *   }
   * });
   *
   * // With full configuration
   * const signal = await DefaultSignalProtocolClient.create('user-123', {
   *   deviceId: 1,
   *   storage,
   *   relay,
   *   protocol: { postQuantum: 'required', braid: 'required' },
   *   onProgress,
   *   enableDebugLogging: true,
   *   ratchetConfig: { maxSkip: 2000 }
   * });
   *
   * // For local development with in-memory adapters
   * const signal = await DefaultSignalProtocolClient.create('local-user', {
   *   protocolManager: inMemoryManager,
   *   storage: inMemoryStorage
   * });
   * ```
   */
  static async create(
    userId: string,
    config: SignalProtocolClientConfig
  ): Promise<DefaultSignalProtocolClient> {
    return DefaultSignalProtocolClient.#createOwned(userId, config);
  }

  static async #createOwned(
    userId: string,
    config: SignalProtocolClientConfig,
    retained?: RetainedIdentities,
  ): Promise<DefaultSignalProtocolClient> {
    const deviceId = config?.deviceId ?? 1; // Default to primary device

    // Use locking to prevent race conditions when multiple create() calls happen concurrently.
    // The lock allows only one storage instance per userId, which prevents database lock
    // contention and session state corruption.
    return storageLock.acquire(`storage-init-${userId}`, async () => {
      // Storage is required - DefaultSignalProtocolClient is platform-agnostic
      // Each platform must provide its own storage implementation
      if (!config?.storage) {
        throw new Error(
          'DefaultSignalProtocolClient.create() requires storage. ' +
            'Expo: import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo"; ' +
            'React Native: import { reactNativeStore } from "@open-e2ee/signal-protocol-sdk/local/store/react-native"; ' +
            'Web: import { webSqliteStore } from "@open-e2ee/signal-protocol-sdk/local/store/web-sqlite", ' +
            'or where OPFS is unavailable, import { indexedDbStore } from "@open-e2ee/signal-protocol-sdk/local/store/web"; ' +
            'Node: import { nodeStore } from "@open-e2ee/signal-protocol-sdk/local/store/node";'
        );
      }

      const finalConfig: SignalProtocolClientConfig = {
        ...config,
        protocolStrategy: resolveSignalProtocolStrategy(config),
        storage: config.storage,
      };
      const activeIdentityTypes = getActiveIdentityTypes(finalConfig);

      if (deviceId > 1 && !retained) {
        for (const identityType of activeIdentityTypes) {
          const hasIdentityKey = await finalConfig.storage.hasIdentityKey(identityType);
          if (!hasIdentityKey) {
            throw new Error(
              `Linked device ${deviceId} requires a provisioned ${identityType.toUpperCase()} identity key in storage. ` +
                'Import the account identity by device transfer or by an application channel, ' +
                'then create the client with that storage.'
            );
          }
        }
      }

      const client = new DefaultSignalProtocolClient(userId, deviceId, finalConfig);
      try {
        await client.initialize(retained);
        await client.hydratePersistedState();
        await migrateRetryRequestRecords(client._storage);
        await client.applyContentRecoveryDecision();
        // A failed sweep fails the start and runs again at the next start.
        await removeDistributionsFromMessageRecords(
          client._storage,
          client.contentAdapter,
          client.logger
        );
        // Delete the handoff rows that a crash or a key write outside the
        // sender-key manager left behind. A failed sweep does not fail the start,
        // because a row with an old senderKeyId never matches the current key.
        try {
          await client.cipher.sweepSenderKeyHandoffs();
        } catch (sweepError) {
          client.logger.warn('Startup sender-key handoff sweep failed', {
            category: 'E2EE',
            data: { error: (sweepError as Error).message },
          });
        }

        // Cleanup expired sessions and resendable content on startup.
        // The reference implementation relies on event-driven cleanup (identity change, retry, end-session).
        // We also enforce our maxRecv TTL here to prevent unbounded session growth.
        try {
          await client.sesameManager.cleanupExpiredSessions();
          await client.resendableContent.sweep();
        } catch (cleanupError) {
          // Non-fatal: cleanup failures should not prevent client creation
          client.logger.debug('Startup session/record cleanup failed', {
            category: 'E2EE',
            data: { error: (cleanupError as Error).message },
          });
        }

        // Auto-sync to server if relay provided
        let syncFailed = false;
        if (finalConfig?.relay) {
          try {
            await client.syncToServer(finalConfig.onProgress);
          } catch (e) {
            client.logger.warn('Initial sync failed, client created in offline mode', {
              category: 'E2EE',
              data: { error: e },
            });
            syncFailed = true;
          }
        }
        client._syncStatus = finalConfig?.relay ? (syncFailed ? 'failed' : 'synced') : 'none';

        // Start relay subscription if relay is configured with onMessageDecrypted hook
        // Only subscribe if sync succeeded - subscriptions require a valid server session
        if (!syncFailed && finalConfig?.relay && finalConfig?.hooks?.onMessageDecrypted) {
          client.startRelaySubscription();
        }

        // Post the stored retry requests whose next attempt time has come, and
        // end the requests past their deadlines. Run the pending resend jobs.
        // The passes run in the background.
        // The receive queue resumes the stored receive records first. With no
        // relay, it serves the helper receives alone.
        if (finalConfig?.relay) client.startRetryRequests();
        else void client.receiveQueue.start();

        // Validate sender keys config and warn on extreme values
        if (finalConfig?.senderKeys) {
          const sk = finalConfig.senderKeys;
          if (sk.maxChainAdvance !== undefined && sk.maxChainAdvance < 100) {
            client.logger.warn(
              'senderKeys.maxChainAdvance < 100 may reject legitimate delayed messages',
              {
                category: 'E2EE',
                data: { value: sk.maxChainAdvance },
              }
            );
          }
          if (sk.maxSkippedKeys !== undefined && sk.maxSkippedKeys > 10000) {
            client.logger.warn('senderKeys.maxSkippedKeys > 10000 may cause memory issues', {
              category: 'E2EE',
              data: { value: sk.maxSkippedKeys },
            });
          }
        }

        return client;
      } catch (failure) {
        if (retained) {
          try {
            await client.stop();
          } catch (cleanupFailure) {
            throw new ClientStartupCleanupError(
              failure, cleanupFailure, () => client.stop()
            );
          }
        }
        throw failure;
      }
    });
  }

  // ============================================================================
  // INITIALIZATION & SETUP
  // ============================================================================

  /**
   * Initialize the Signal Protocol on this device (private - called by create())
   *
   * Generates identity keys if they do not exist and prepares the client for use.
   */
  private async initialize(retained?: RetainedIdentities): Promise<void> {
    try {
      const types = getActiveIdentityTypes(this.config);
      if (retained) {
        if (!(this.manager instanceof DefaultSignalProtocolManager)) {
          throw new TypeError('Retained startup requires the SDK protocol manager.');
        }
        await initializeManagerFromRetainedIdentities(this.manager, types, retained);
      } else await this.manager.initialize(types);

      // Set local identity so manager knows who we are for session operations
      // This is needed even without server sync (local-only mode)
      this.manager.setLocalIdentity(this.userId, this.deviceId);

      // UserID is plain string, DeviceID is plain number - no cast needed
      await this.sesameManager.initialize(this.userId, this.deviceId);
      this.logger.debug('Signal Protocol initialized', {
        category: 'E2EE',
        data: { userId: this.userId, deviceId: this.deviceId },
      });
    } catch (error) {
      if (retained) throw error;
      throw new EncryptionError(
        'Failed to initialize Signal Protocol',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Sync the public prekey bundle to the configured relay.
   *
   * create() calls this automatically when config names a relay.
   * Callers can also run it manually to retry after a failed initial sync.
   *
   * Delegates to PreKeyOps.syncToServer for implementation.
   */
  async syncToServer(onProgress?: ProgressCallback): Promise<void> {
    await PreKeyOps.syncToServer(this.ctx, onProgress);
    this._syncStatus = 'synced';
  }

  /**
   * Explicitly rotate this account's relay identity using a caller-authenticated
   * compare-and-swap commitment, then publish fresh prekeys for that namespace.
   * Normal sync and the managed device link never call this operation.
   */
  async rotateAccountIdentity(
    expectedCurrentCommitment: Uint8Array,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    if (!this.config.relay) {
      throw new EncryptionError(
        'Relay server not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    if (expectedCurrentCommitment.length !== 32) {
      throw new Error('Expected current identity commitment must contain exactly 32 bytes');
    }
    const replacement = await this._storage.getIdentityKey(identityType);
    if (!replacement) {
      throw new Error(`Cannot rotate missing local ${identityType.toUpperCase()} identity`);
    }

    this._syncStatus = 'failed';
    try {
      await this.config.relay.rotateIdentityKey({
        userId: this.userId,
        deviceId: this.deviceId,
        identity: createCompositeIdentityV1(replacement),
        registrationId: replacement.registrationId,
        identityType,
        expectedCurrentCommitment,
      });
      await PreKeyOps.syncIdentityToServer(this.ctx, identityType);
      this._syncStatus = 'synced';
    } catch (error) {
      // A relay may have committed the CAS rotation before a later prekey
      // upload failed. Keep the client explicitly offline. syncToServer() is
      // the idempotent recovery operation for that availability-only gap.
      this._syncStatus = 'failed';
      throw error;
    }
  }

  // ============================================================================
  // Key Recovery / Forced Rotation
  // ============================================================================

  /**
   * Force prekey rotation: generate new keys with fresh IDs and upload.
   *
   * Called automatically on stale prekey detection and as recovery for
   * PQXDH §4.13 identifier collisions.
   *
   * Delegates to PreKeyOps.regeneratePreKeysWithFreshIds for implementation.
   */
  /**
   * Hydrate state from persistent storage.
   */
  /**
   * Report the content recovery decision once, and delete the resendable
   * content that a refused store still holds from an earlier policy. The
   * clear deletes no sender key state, so the next group send needs no new
   * distribution.
   */
  private async applyContentRecoveryDecision(): Promise<void> {
    const status = this._contentRecoveryStatus;
    const data = {
      level: status.level,
      mode: status.mode,
      atRest: status.atRest,
      keyCustody: status.keyCustody,
      reason: status.reason,
      groupMembershipSource: status.groupMembershipSource,
    };
    if (status.enabled) {
      if (status.groupMembershipSource === 'none') {
        this.logger.warn(
          'Content recovery has no group membership source, so the client refuses each group ' +
            'resend. Configure `groups` for managed groups, or set ' +
            '`protocol.contentRecovery.isCurrentMember` for ad hoc groups',
          { category: 'E2EE', data }
        );
      }
      if (status.level === 'co-located') {
        this.logger.warn(
          'Content recovery keeps resendable content in a store whose key shares its storage ' +
            "(protocol.contentRecovery.mode 'allow-co-located-key')",
          { category: 'E2EE', data }
        );
      }
      await this.resendableContent.keepContent();
      return;
    }
    if (status.reason === 'co-located-key-not-allowed') {
      this.logger.error(
        'Content recovery is off: the local store key shares the storage of the data. ' +
          "Use a keychain or application vault, or set protocol.contentRecovery.mode to 'allow-co-located-key'",
        { category: 'E2EE', data }
      );
    } else if (status.reason === 'unprotected-store') {
      this.logger.warn('Content recovery is off: the local store has no encryption at rest', {
        category: 'E2EE',
        data,
      });
    } else {
      this.logger.info('Content recovery is off by policy', { category: 'E2EE', data });
    }
    await this.resendableContent.clear();
  }

  /**
   * The content hint of a group send. A `DataMessage` send is `Resendable`
   * unless the application sets another hint. A `Resendable` send keeps its
   * content in the send log, so the sender can answer a retry request with
   * it. When content recovery is off, or the send is a string or bytes with
   * no content timestamp, the sender cannot answer. The send then goes out
   * as `Default`, so no recipient waits for an answer, and the client logs
   * the downgrade once.
   */
  private groupContentHint(
    requested: ContentHint | undefined,
    dataMessage: boolean
  ): ContentHint | undefined {
    if (requested !== undefined && requested !== ContentHint.Resendable) return requested;
    if (requested === undefined && !dataMessage) return undefined;
    const status = this._contentRecoveryStatus;
    if (dataMessage && status.enabled) return ContentHint.Resendable;
    if (!this.resendableDowngradeLogged) {
      this.resendableDowngradeLogged = true;
      this.logger.info('A group send goes out as Default, because the sender keeps no content to resend', {
        category: 'E2EE',
        data: {
          contentRecovery: status.enabled ? 'enabled' : 'disabled',
          ...(status.reason && { reason: status.reason }),
          dataMessage,
        },
      });
    }
    return ContentHint.Default;
  }

  /**
   * Delete expired resendable content before the first resendable group
   * send of the day. A failed sweep does not stop the send. The next sweep
   * deletes the content.
   */
  private async sweepResendableContentDaily(): Promise<void> {
    try {
      await this.resendableContent.sweepDaily();
    } catch (error) {
      this.logger.warn('Error cleaning up resendable content', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }
  }

  private async hydratePersistedState(): Promise<void> {
    try {
      const stored = await this._storage.getMetadata('lastForcedPreKeyRotation');
      if (stored) {
        const timestamp = parseInt(stored, 10);
        if (!isNaN(timestamp) && timestamp > 0) {
          this.state.setLastPreKeyRotationTime(timestamp);
        }
      }
    } catch (error) {
      // Best-effort: if storage read fails, start with timestamp 0.
      // Next stale-prekey error will trigger rotation immediately (safe).
      this.logger.debug('Failed to hydrate persisted rotation state', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }
  }

  private async regeneratePreKeysWithFreshIds(): Promise<void> {
    await PreKeyOps.regeneratePreKeysWithFreshIds(this.ctx);
    const now = Date.now();
    // Update debounce timestamp so concurrent call sites (relay-subscription + retry.ts)
    // do not both trigger rotation for the same stale prekey event.
    this.state.setLastPreKeyRotationTime(now);
    // Persist the debounce timestamp across application restarts.
    await this._storage.setMetadata('lastForcedPreKeyRotation', String(now));
  }

  /**
   * Verify server has correct keys after upload.
   *
   * Delegates to PreKeyOps.verifyServerKeys for implementation.
   */
  private async verifyServerKeys(
    signedPreKey: { keyId: number; publicKey: string },
    kyberPreKey: { keyId: number; publicKey: string } | null,
    operation: string
  ): Promise<void> {
    return PreKeyOps.verifyServerKeys(this.ctx, signedPreKey, kyberPreKey, operation);
  }

  /**
   * Force complete key reset (development/debugging only).
   *
   * Delegates to PreKeyOps.forceCompleteKeyReset for implementation.
   */
  async forceCompleteKeyReset(): Promise<PreKeyOps.ForceKeyResetResult> {
    const result = await PreKeyOps.forceCompleteKeyReset(this.ctx);

    // Clear internal tracking state via state manager
    this.state.clearForStop();

    return result;
  }

  /**
   * Check whether the client completed initialization
   *
   * @returns True if identity keys exist and client is ready to use
   */
  async isInitialized(): Promise<boolean> {
    return await this._storage.hasIdentityKey();
  }

  /**
   * Get client's identity public key
   *
   * @returns Public key for this device's identity
   */
  async getIdentityPublicKey(): Promise<PublicKey> {
    const identityKey = await this._storage.getIdentityKey();
    if (!identityKey) {
      throw new EncryptionError(
        'Identity key not found - client not initialized',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    return identityKey.signingKey.publicKey;
  }

  /**
   * Get the ProtocolAddress for this client's device.
   *
   * Useful when an integration needs to reference the local device.
   *
   * @returns ProtocolAddress for this client (userId:deviceId)
   *
   * @example
   * ```typescript
   * const alice = await DefaultSignalProtocolClient.create('alice', { storage: aliceStorage });
   * const bob = await DefaultSignalProtocolClient.create('bob', { storage: bobStorage });
   *
   * // Use address() to reference the local device
   * await alice.encryptMessage(bob.address(), 'Hello');
   * await bob.decryptMessage(alice.address(), encrypted);
   *
   * // Access userId if needed
   * console.log(alice.address().userId); // 'alice'
   * ```
   */
  address(): ProtocolAddress {
    return this._address;
  }

  // ============================================================================
  // SESSION MANAGEMENT
  // ============================================================================

  /**
   * Establish a new session with a specific remote device.
   *
   * Advanced direct-device API. Normal app code can call `send(recipientUserId, content)`.
   * The client will fetch remote device bundles through the configured relay and
   * use the selected protocol policy. Direct callers must provide the remote
   * device's prekey bundle themselves.
   *
   * @param remoteAddress - Partner's protocol address (userId + deviceId)
   * @param prekeyBundle - Partner's prekey bundle (fetched from server)
   *
   * @example
   * ```typescript
   * import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';
   *
   * const remoteAddress = ProtocolAddress.create('bob', 1);
   * const bundle = await relay.fetchPreKeyBundle(remoteAddress.userId);
   * await signal.establishSession(remoteAddress, bundle);
   * ```
   */
  async establishSession(
    remoteAddress: ProtocolAddress,
    prekeyBundle: PreKeyBundle,
    recipientIdentityType: IdentityType = 'aci'
  ): Promise<void> {
    return SessionOps.establishSession(
      this.ctx,
      this.sesameManager,
      remoteAddress,
      prekeyBundle,
      recipientIdentityType
    );
  }

  /**
   * Check if a session exists
   *
   * @param remoteAddress - Remote device's protocol address
   * @returns True if session exists
   */
  async hasSession(remoteAddress: ProtocolAddress): Promise<boolean> {
    return SessionOps.hasSession(this.ctx, remoteAddress);
  }

  /**
   * Delete a session
   *
   * Use this to reset encryption for a session (e.g., after a security incident).
   * You will need to establish a new session before sending/receiving messages.
   *
   * @param remoteAddress - Remote device's protocol address
   */
  async deleteSession(remoteAddress: ProtocolAddress): Promise<void> {
    return SessionOps.deleteSession(this.ctx, remoteAddress);
  }

  /**
   * Archive a session after a stale-device response.
   *
   * Moves current session to inactive list, preserving it for delayed message decryption.
   * Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"
   *
   * Use this when handling stale device errors (410). The old session may still
   * decrypt messages that were in-flight during the session refresh.
   *
   * @param remoteAddress - Remote device's protocol address
   */
  async archiveSession(remoteAddress: ProtocolAddress): Promise<void> {
    return SessionOps.archiveSession(this.ctx, remoteAddress);
  }

  /**
   * Mark a message as delivered, silently ignoring errors.
   *
   * Used when discarding undecryptable messages (IMPLICIT content, stale prekeys)
   * to prevent them from reappearing in the queue.
   *
   * @param envelopeId - The envelope ID to mark as delivered
   * @param options - Decryption options containing optional markDelivered callback
   */
  private async markMessageDeliveredSilently(
    envelopeId: string | undefined,
    options?: { markDelivered?: (id: string) => Promise<void> }
  ): Promise<void> {
    if (!envelopeId) return;

    if (this.relay?.markDelivered) {
      await this.relay.markDelivered(envelopeId).catch((_error) => {
        this.logger.warn('Failed to mark delivered', {
          category: 'E2EE',
          data: { envelopeId },
        });
      });
    } else if (options?.markDelivered) {
      await options.markDelivered(envelopeId).catch((_error) => {
        this.logger.warn('Failed to mark delivered', {
          category: 'E2EE',
          data: { envelopeId },
        });
      });
    }
  }

  // ============================================================================
  // MESSAGE ENCRYPTION/DECRYPTION (delegated to messages.ts)
  // ============================================================================

  /** @see MessageOps.encryptMessage */
  async encryptMessage(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext> {
    return MessageOps.encryptMessage(this.ctx, remoteAddress, plaintext);
  }

  /**
   * Decrypt a message from a session
   *
   * Uses the Double Ratchet algorithm to decrypt ciphertext, handling
   * out-of-order messages and updating session state.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param ciphertext - Message to decrypt
   * @returns Decrypted plaintext
   */
  async decryptMessage(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string> {
    return MessageOps.decryptMessage(this.ctx, remoteAddress, ciphertext);
  }

  /**
   * Encrypt multiple messages in batch
   *
   * More efficient than calling encryptMessage() multiple times.
   * The method runs all operations atomically. If any encryption fails,
   * it encrypts none of the messages.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param plaintexts - Array of messages to encrypt
   * @returns Array of encrypted ciphertexts in the same order
   */
  async encryptMessages(
    remoteAddress: ProtocolAddress,
    plaintexts: string[]
  ): Promise<Ciphertext[]> {
    return MessageOps.encryptMessages(this.ctx, remoteAddress, plaintexts);
  }

  /**
   * Decrypt multiple messages in batch
   *
   * More efficient than calling decryptMessage() multiple times.
   * Handles out-of-order messages correctly.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param ciphertexts - Array of messages to decrypt
   * @returns Array of decrypted plaintexts in the same order
   */
  async decryptMessages(
    remoteAddress: ProtocolAddress,
    ciphertexts: Ciphertext[]
  ): Promise<string[]> {
    return MessageOps.decryptMessages(this.ctx, remoteAddress, ciphertexts);
  }

  /**
   * Process an incoming encrypted message envelope.
   *
   * The receive helper for an application that pulls envelopes itself. It
   * decrypts the envelope and commits its content as a receive record with
   * the ratchet step, then decides the group of the content. The content
   * stays recoverable until the application calls `completeReceive`, or
   * until `onPersist` resolves.
   *
   * The outcome tells the caller what to do with the envelope:
   *
   * - `processed`: give the content to the application, then acknowledge
   *   the envelope. A redelivery of the envelope before `completeReceive`
   *   returns the same outcome again with no second decrypt.
   * - `pending`: the content is stored, and its group state must update
   *   first. Acknowledge the envelope. The client decides the content again
   *   when the group updates, and `listPendingReceives({ ready: true })`
   *   then lists it.
   * - `duplicate`: this client processed the envelope, or the application
   *   already has the content of the failed envelope of a retry request.
   *   The client acknowledged the envelope.
   * - `null-message`: the envelope carries no content. The client consumed
   *   it and acknowledged it. A null message for a failed envelope marks
   *   that envelope processed, but a content resend for it that comes later
   *   still gives its content.
   * - `denied`: the client refused the content. The ratchet step is spent,
   *   and the client acknowledged the envelope. Content from another
   *   account that carries a sync message is denied in any envelope.
   * - `refused`: the receive queue has no room. Nothing is decrypted or
   *   stored. Do not acknowledge the envelope. Give it again later.
   *
   * On a retryable decrypt failure the client sends a SESAME retry request,
   * which acknowledges the envelope, and throws the error. A message with
   * the Implicit content hint gets no request and is acknowledged.
   *
   * A `retry_request` envelope holds no plaintext. This method rejects it
   * before decryption and sends no retry request. Give it to
   * `receiveIncomingEnvelopes`, which handles it.
   *
   * A resend that brings only the sender key of a failed group message
   * gives no content. It does not mark the failed envelope processed, so a
   * redelivery of that envelope decrypts with the key.
   *
   * @param envelope - The encrypted message envelope
   * @param options - Transport callbacks for background (no relay)
   *   scenarios, and `onPersist`
   * @returns The receive outcome
   * @throws EncryptionError after sending retry request if decryption fails
   * @throws EncryptionError INVALID_CIPHERTEXT for a `retry_request` envelope,
   *   identified or sealed
   */
  async processIncomingEnvelope(
    envelope: IncomingEnvelope,
    options?: ProcessEnvelopeOptions
  ): Promise<ReceiveOutcome> {
    return (await this.receiveForCaller(envelope, options)).outcome;
  }

  /**
   * Complete a helper receive: delete its receive record and mark its
   * envelope processed. Call it after the application stored the content
   * of a `processed` outcome. An unknown or completed message ID is a no-op.
   *
   * @param messageId - The `messageId` of the `processed` outcome
   */
  async completeReceive(messageId: string): Promise<void> {
    let after: ReceiveWorkQuery['after'];
    for (;;) {
      const page = await this._storage.listReceiveWork({
        stage: 'awaiting-completion',
        ...(after !== undefined && { after }),
        limit: RECEIVE_WORK_DEFAULT_LIMIT,
      });
      const record = page.find(
        (item) => item.origin === 'caller' && (item.messageId ?? item.workId) === messageId
      );
      if (record) {
        await this.completeCallerRecord(record.workId);
        return;
      }
      if (page.length < RECEIVE_WORK_DEFAULT_LIMIT) return;
      const last = page[page.length - 1]!;
      after = { arrivalSeq: last.arrivalSeq, workId: last.workId };
    }
  }

  /**
   * List the stored receives in arrival order, one page at a time. A receive
   * whose content the application has, and whose receipt waits, is not
   * listed.
   *
   * @param query - `ready` lists only the helper receives whose content
   *   waits for `completeReceive`. `after` is the `next` value of the page
   *   before. `limit` is the page size, 100 by default.
   * @returns The page, and `next` when a later page can follow
   * @throws Error when `after` is not a `next` value or `limit` is not a
   *   positive integer
   */
  async listPendingReceives(
    query: { ready?: boolean; after?: string; limit?: number } = {}
  ): Promise<{ items: PendingReceive[]; next?: string }> {
    const limit = query.limit ?? RECEIVE_WORK_DEFAULT_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new Error('listPendingReceives limit must be a positive integer');
    }
    let after: ReceiveWorkQuery['after'];
    if (query.after !== undefined) {
      // The `next` value is `<arrivalSeq>:<workId>`. An `arrivalSeq` is not
      // unique, so the cursor holds both values.
      const match = /^(\d+):([\s\S]+)$/.exec(query.after);
      const arrivalSeq = match ? Number(match[1]) : Number.NaN;
      if (!Number.isSafeInteger(arrivalSeq)) {
        throw new Error('listPendingReceives after must be the next value of an earlier page');
      }
      after = { arrivalSeq, workId: match![2]! };
    }
    const items: PendingReceive[] = [];
    for (;;) {
      const page = await this._storage.listReceiveWork({
        ...(query.ready === true && { stage: 'awaiting-completion' as const }),
        ...(after !== undefined && { after }),
        limit,
      });
      for (const record of page) {
        after = { arrivalSeq: record.arrivalSeq, workId: record.workId };
        if (record.stage === 'receipt-due') continue;
        items.push(this.pendingReceiveOf(record));
        if (items.length === limit) {
          return { items, next: `${record.arrivalSeq}:${record.workId}` };
        }
      }
      if (page.length < limit) return { items };
    }
  }

  /**
   * Remove one stored receive that the application gives up on, such as a
   * receive whose `onMessageDecrypted` hook fails at each start. The client
   * deletes the receive and marks its envelope processed, so a redelivery
   * of the envelope is a duplicate. The call sends no receipt, calls no
   * hook, and runs no `onReceiveExpired`. A hook call that already started
   * for the receive still runs, and no receipt follows it.
   *
   * @param messageId - The `messageId` of a receive that
   *   `listPendingReceives` lists
   * @returns The removed receive, or null when the client removed nothing:
   *   no listed receive has the ID, or another path wrote the receive during
   *   the call and again after one read
   */
  async discardPendingReceive(messageId: string): Promise<PendingReceive | null> {
    let record: ReceiveWorkRecord | undefined;
    let after: ReceiveWorkQuery['after'];
    while (record === undefined) {
      const page = await this._storage.listReceiveWork({
        ...(after !== undefined && { after }),
        limit: RECEIVE_WORK_DEFAULT_LIMIT,
      });
      record = page.find(
        (item) => item.stage !== 'receipt-due' && (item.messageId ?? item.workId) === messageId
      );
      if (record === undefined && page.length < RECEIVE_WORK_DEFAULT_LIMIT) return null;
      const last = page[page.length - 1];
      if (last !== undefined) after = { arrivalSeq: last.arrivalSeq, workId: last.workId };
    }
    // The delete checks the revision. A record that another path wrote is
    // read again once.
    for (let attempt = 0; ; attempt++) {
      if (await completeReceiveWork(this.ctx, record, 'expired')) {
        this.receiveQueue.forget(record.workId);
        // A later receive of the conversation can wait behind this one.
        this.receiveQueue.wake();
        return this.pendingReceiveOf(record);
      }
      if (attempt === 1) return null;
      const current = await this._storage.getReceiveWork(record.workId);
      if (current === null || current.stage === 'receipt-due') return null;
      record = current;
    }
  }

  /**
   * Run one pass of the receive queue now, and stop between records at the
   * deadline. A host that wakes for a push calls it after it acknowledged
   * the pulled envelopes.
   *
   * @param options - `deadlineMs` bounds the pass. With no deadline, the
   *   pass runs until each record is handled.
   * @returns The receives that the pass handled, and the receives that
   *   still wait
   */
  async processPendingReceives(
    options: { deadlineMs?: number } = {}
  ): Promise<{ processed: number; remaining: number }> {
    const { processed, remaining } = await this.receiveQueue.processPending(options);
    return { processed, remaining };
  }

  /**
   * Decrypt one envelope with no receive record.
   *
   * The decrypt installs a sender key distribution that the content
   * carries, and checks that a managed group context binds to the group of
   * the transport. It stores no content, decides no group state, and sends
   * no receipt.
   *
   * Warning: the decrypt spends the ratchet step. When the application
   * loses the returned plaintext, no later decrypt of the envelope gives it
   * again. Use `processIncomingEnvelope`, which keeps the content until the
   * application completes the receive.
   *
   * @param envelope - The encrypted message envelope
   * @returns The plaintext as its sender gave it, and the group context of
   *   managed-group content
   * @throws EncryptionError when the decrypt fails, and INVALID_CIPHERTEXT
   *   for a `retry_request` envelope, identified or sealed
   * @throws GroupReceiveRefusedError when the group context is malformed or
   *   names another group than the transport
   */
  async decryptEnvelope(
    envelope: IncomingEnvelope
  ): Promise<{ plaintext: string; groupContext?: GroupContentContext }> {
    if (envelope.messageType === 'retry_request') {
      throw new EncryptionError(
        'A retry_request envelope holds no plaintext; give it to receiveIncomingEnvelopes',
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType, senderId: envelope.senderUserId }
      );
    }
    let commit: Awaited<ReturnType<SignalProtocolServiceCipher['commitEnvelope']>>;
    try {
      commit = await this.cipher.commitEnvelope(this.relayEnvelopeOf(envelope), {
        sealedSender: this.config.sealedSender,
      });
    } catch (error) {
      if (error instanceof SealedRetryRequestReceived) {
        throw new EncryptionError(
          'A sealed retry_request envelope holds no plaintext; give it to receiveIncomingEnvelopes',
          EncryptionErrorCode.INVALID_CIPHERTEXT,
          { messageType: 'retry_request', senderId: error.envelope.senderUserId }
        );
      }
      throw error;
    }
    if (commit.kind === 'denied') throw commit.error;
    if (commit.kind !== 'committed') {
      throw new Error('A decrypt with no receive record committed one');
    }
    const { content } = commit;
    const claim = classifyGroupContent(
      content.messageType === 'sender_key' ? content.transportGroupId : null,
      content.inspected
    );
    let groupContext: GroupContentContext | undefined;
    if (claim) {
      const group = groupOfContext(claim);
      if ('denial' in group) throw new GroupReceiveRefusedError(group.denial);
      groupContext = group.context;
    }
    return {
      plaintext: this.contentAdapter.withoutGroupContext(content.plaintext),
      ...(groupContext !== undefined && { groupContext }),
    };
  }

  /** The Relay envelope of an envelope that the application passed. */
  private relayEnvelopeOf(envelope: IncomingEnvelope): Envelope {
    return {
      ...envelope,
      targetUserId: this.userId,
      targetDeviceId: this.deviceId,
      deliveryClass: 'user-visible',
      messageType: (envelope.messageType ?? 'ciphertext') as Envelope['messageType'],
    };
  }

  /**
   * Receive one envelope that the application passed. The queue skips its
   * record while the receive runs, and runs a pass after it.
   *
   * @param direct - The group and the receive record ID of a framed group
   *   message that `decryptGroupMessage` passed. A decrypt failure then
   *   throws with no retry request and no report.
   * @returns The outcome, and the error behind a `pending` or `denied`
   *   outcome
   */
  private async receiveForCaller(
    envelope: IncomingEnvelope,
    options: ProcessEnvelopeOptions | undefined,
    direct?: { readonly groupId: string; readonly workId: string; readonly framed: Uint8Array }
  ): Promise<{ outcome: ReceiveOutcome; error?: Error }> {
    if (envelope.messageType === 'retry_request') {
      throw new EncryptionError(
        'A retry_request envelope holds no plaintext; give it to receiveIncomingEnvelopes',
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType, senderId: envelope.senderUserId }
      );
    }
    // The fingerprint covers the envelope as the Relay delivered it, before
    // any unseal, so every receive path stores one value for it.
    const workId =
      direct?.workId ?? (await deliveredEnvelopeFingerprint(this.userId, this.deviceId, envelope));
    const release = this.receiveQueue.hold(workId);
    try {
      // The record sorts after the stored records once the resume ends. The
      // wait comes before the retry family lock, which the resume also takes.
      await this.receiveQueue.seeded();
      return await receiveInRetryFamily(
        this._storage,
        this.logger,
        this.hooks,
        envelope,
        (family) => this.receiveForCallerLocked(envelope, family, workId, options, direct)
      );
    } finally {
      release();
      this.receiveQueue.wake();
    }
  }

  /** Receive one envelope that the application passed, under its retry family lock. */
  private async receiveForCallerLocked(
    envelope: IncomingEnvelope,
    family: RetryFamilyReceive,
    workId: string,
    options: ProcessEnvelopeOptions | undefined,
    direct:
      | { readonly groupId: string; readonly workId: string; readonly framed: Uint8Array }
      | undefined
  ): Promise<{ outcome: ReceiveOutcome; error?: Error }> {
    // The processed record of an envelope with no ID has no key.
    const receiveId = envelope.id ? workId : undefined;
    let record = await this._storage.getReceiveWork(workId);
    if (record) {
      // The application got the content. Only its receipt can wait.
      if (record.plaintext === undefined) {
        await this.markMessageDeliveredSilently(envelope.id, options);
        return { outcome: { kind: 'duplicate' } };
      }
      if (!record.awaitingEnvelope) {
        // The receive queue delivers a Relay record to onMessageDecrypted.
        if (record.origin === 'relay') {
          return {
            outcome: { kind: 'pending', messageId: record.messageId ?? workId, reason: 'queued' },
          };
        }
        // A redelivery of content that waits for completeReceive.
        if (record.stage === 'awaiting-completion') {
          return { outcome: await this.processedReceive(record, options) };
        }
      } else {
        // A converted legacy record gets its sender from this envelope.
        const opened = await this.openForCaller(envelope, family, receiveId, options);
        record = await this.fillAwaitingRecord(record, family, workId, opened);
      }
    } else {
      if (!(await family.admit(receiveId))) {
        await this.markMessageDeliveredSilently(envelope.id, options);
        return { outcome: { kind: 'duplicate' } };
      }
      const opened = await this.openForCaller(envelope, family, receiveId, options);
      const decrypted = await this.decryptForCaller(
        envelope,
        opened,
        family,
        workId,
        options,
        direct
      );
      if ('outcome' in decrypted) return decrypted;
      record = decrypted.record;
    }

    // The record names the sender that its decrypt authenticated. A
    // redelivery of a committed record runs no seed, so it binds here.
    family.bindSender(record);
    const restored = await this.cipher.restoreCommitted(record);
    // The ratchet step is spent, so a resend cannot repair the content.
    if (restored.kind === 'denied') {
      await denyReceiveWork(this.ctx, record, restored, restored.error);
      await this.markMessageDeliveredSilently(envelope.id, options);
      return {
        outcome: { kind: 'denied', reason: receiveDenialReason(restored.error) },
        error: restored.error,
      };
    }
    const { content } = restored;
    // A null message carries no content, so the caller never gets it.
    if (content.inspected.nullMessage) {
      await family.consumeNull(receiveId);
      await completeReceiveWork(this.ctx, record);
      await this.markMessageDeliveredSilently(envelope.id, options);
      return { outcome: { kind: 'null-message' } };
    }
    // Outcome 1 comes before the return. A redelivery after a failed write
    // finds the committed record and writes it again, as on the Relay path.
    await family.fulfill({
      senderKeyDistribution: content.inspected.senderKeyDistribution !== undefined,
      content:
        content.inspected.senderKeyDistribution === undefined ||
        content.inspected.senderKeyDistributionOnly === false,
      ...RelaySubscriptionOps.groupOfFulfill(content),
    });
    const decision = await this.cipher.decideGroupContent(content);
    if (decision.kind === 'denied') {
      await denyReceiveWork(this.ctx, record, content, decision.error);
      await this.markMessageDeliveredSilently(envelope.id, options);
      return { outcome: { kind: 'denied', reason: decision.error.reason }, error: decision.error };
    }
    const expiresAt = receiveExpiresAt(record);
    if (decision.kind === 'unavailable') {
      await blockReceiveWork(this.ctx, record, content, decision, Date.now(), expiresAt);
      return {
        outcome: { kind: 'pending', messageId: content.messageId, reason: decision.error.reason },
        error: decision.error,
      };
    }
    const awaiting =
      (await awaitReceiveCompletion(this.ctx, record, decision.groupId, expiresAt)) ??
      (await this._storage.getReceiveWork(workId)) ??
      record;
    return { outcome: await this.processedReceive(awaiting, options) };
  }

  /**
   * Open the seal of a sealed envelope that the application passed. A
   * member whose seal fails to open asks the device of its request for the
   * next attempt, as a member whose decrypt fails does.
   *
   * @returns The envelope inside the seal, or the envelope itself
   * @throws EncryptionError INVALID_CIPHERTEXT for a sealed retry request
   */
  private async openForCaller(
    envelope: IncomingEnvelope,
    family: RetryFamilyReceive,
    receiveId: string | undefined,
    options: ProcessEnvelopeOptions | undefined
  ): Promise<{ inner: IncomingEnvelope; arrivedSealed: boolean }> {
    if (envelope.messageType !== 'unidentified_sender' || !this.config.sealedSender) {
      return { inner: envelope, arrivedSealed: false };
    }
    const identityKeyPair = await this._storage.getIdentityKey();
    if (!identityKeyPair) {
      throw new EncryptionError(
        'No identity key pair for sealed sender decryption',
        EncryptionErrorCode.DECRYPTION_FAILED
      );
    }
    let unsealed: Awaited<ReturnType<typeof unsealMessage>>;
    try {
      unsealed = await unsealMessage(
        envelope.ciphertext,
        base64ToBytes(identityKeyPair.dhKey.privateKey),
        this.userId,
        this.deviceId,
        this.config.sealedSender,
        envelope.serverTimestamp,
        this.logger
      );
    } catch (error) {
      if (family.member !== undefined) {
        await this.sendRetryRequestInternal(
          family.withRequestedSender(envelope),
          error as Error,
          family,
          receiveId,
          options
        );
      }
      throw error;
    }
    // A sealed retry request holds no plaintext, as an identified one.
    // It asks for no resend of itself.
    if (unsealed.contentType === SealedSenderContentType.PLAINTEXT_CONTENT) {
      throw new EncryptionError(
        'A sealed retry_request envelope holds no plaintext; give it to receiveIncomingEnvelopes',
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: 'retry_request', senderId: unsealed.senderUserId }
      );
    }
    // The inner type and the content hint travel inside the seal. The same
    // mapping serves the other receive path via `reconstructEnvelope`.
    return {
      inner: {
        ...envelope,
        senderUserId: unsealed.senderUserId,
        senderDeviceId: unsealed.senderDeviceId,
        ciphertext: unsealed.innerCiphertextBase64,
        messageType: envelopeTypeForContent(unsealed.contentType),
        contentHint: unsealed.contentHint,
      },
      arrivedSealed: true,
    };
  }

  /** The receive commit of an envelope that the application passed. */
  private callerReceiveCommit(family: RetryFamilyReceive, workId: string) {
    return createReceiveCommit({
      storage: this._storage,
      policy: this.receiveQueue.policy,
      logger: this.logger,
      contentAdapter: this.contentAdapter,
      family,
      workId,
      origin: 'caller',
      receiptJoin: false,
    });
  }

  /**
   * Fill the sender fields of a converted legacy record from the envelope
   * that the application passed. The record keeps its age and its arrival
   * order, and becomes a helper record.
   */
  private async fillAwaitingRecord(
    existing: ReceiveWorkRecord,
    family: RetryFamilyReceive,
    workId: string,
    opened: { inner: IncomingEnvelope; arrivedSealed: boolean }
  ): Promise<ReceiveWorkRecord> {
    const { inner, arrivedSealed } = opened;
    const groupId =
      existing.groupId ??
      (inner.messageType === 'sender_key'
        ? ((await this.senderKeyManager.resolveGroupForFramedMessage(
            envelopeCiphertextBytes(inner.ciphertext),
            inner.senderUserId,
            inner.senderDeviceId
          )) ?? undefined)
        : undefined);
    const seed = this.callerReceiveCommit(family, workId).commit.seed(
      this.relayEnvelopeOf(inner),
      arrivedSealed
    );
    const filled = sizedReceiveWork({
      ...seed({ plaintext: existing.plaintext!, ...(groupId !== undefined && { groupId }) }),
      workId: existing.workId,
      revision: existing.revision + 1,
      stage: existing.stage,
      arrivalSeq: existing.arrivalSeq,
      receivedAt: existing.receivedAt,
      dueAt: existing.dueAt,
      plaintext: existing.plaintext!,
      ...(groupId !== undefined && { groupId }),
      ...(existing.blockedOn !== undefined && { blockedOn: existing.blockedOn }),
    });
    if (await this._storage.putReceiveWork(filled, existing.revision)) return filled;
    return (await this._storage.getReceiveWork(workId)) ?? existing;
  }

  /**
   * Decrypt one opened envelope under the receive admission, and commit its
   * receive record with the ratchet step.
   *
   * A decrypt failure that no resend can repair, as `receiveRefusal`
   * decides on both receive paths, asks for nothing: `onDecryptionError`
   * runs once, the envelope is stored as processed and acknowledged, and
   * the outcome is `denied`. A retryable failure (per SESAME spec §4.1)
   * sends a retry request, which acknowledges the envelope, and throws. A
   * failure after the decrypt built the record is a store failure: it
   * throws with no request, and the ratchet step rolled back.
   *
   * @returns The committed record, or the outcome when nothing committed
   */
  private async decryptForCaller(
    envelope: IncomingEnvelope,
    opened: { inner: IncomingEnvelope; arrivedSealed: boolean },
    family: RetryFamilyReceive,
    workId: string,
    options: ProcessEnvelopeOptions | undefined,
    direct: { readonly groupId: string; readonly framed: Uint8Array } | undefined
  ): Promise<{ record: ReceiveWorkRecord } | { outcome: ReceiveOutcome; error?: Error }> {
    const { inner, arrivedSealed } = opened;
    const receiveId = envelope.id ? workId : undefined;
    const handle = this.callerReceiveCommit(family, workId);
    const failure = { reported: false };
    let admitted: { value: string } | null;
    try {
      const seed = handle.commit.seed(this.relayEnvelopeOf(inner), arrivedSealed);
      if (inner.messageType === 'sender_key') {
        // `sender_key` says the payload is a framed SenderKeyMessage. It
        // does not say which group, so the group comes from the frame's
        // distribution identifier resolved against the local sender key
        // store.
        const framed = direct?.framed ?? envelopeCiphertextBytes(inner.ciphertext);
        const groupId =
          direct?.groupId ??
          (await this.senderKeyManager.resolveGroupForFramedMessage(
            framed,
            inner.senderUserId,
            inner.senderDeviceId
          ));
        if (groupId === null) {
          throw new EncryptionError(
            `No sender key from ${inner.senderUserId} matches this group message - request key distribution`,
            EncryptionErrorCode.SESSION_NOT_FOUND
          );
        }
        admitted = await this.groupSenderKeys.run(groupId, (rawGroupId) =>
          handle.commit.admit(rawGroupId, () =>
            GroupOps.decryptGroupMessage(
              this.ctx,
              this.senderKeyManager,
              rawGroupId,
              inner.senderUserId,
              inner.senderDeviceId,
              framed,
              seed
            )
          )
        );
      } else {
        // Decode ciphertext: base64 → UTF-8 bytes → JSON string
        const ciphertext = utf8Decode(envelopeCiphertextBytes(inner.ciphertext)) as Ciphertext;
        const address = ProtocolAddress.create(inner.senderUserId, inner.senderDeviceId);
        admitted = await handle.commit.admit(null, async () => {
          // The failure of the decrypt runs onDecryptionError.
          try {
            return await MessageOps.decryptMessage(this.ctx, address, ciphertext, seed);
          } catch (error) {
            failure.reported = true;
            throw error;
          }
        });
      }
    } catch (error) {
      if (handle.seeded() || direct !== undefined) throw error;
      if (receiveRefusal(error) !== null) {
        await reportReceiveRefusal(
          this._storage,
          this.hooks,
          inner,
          error as Error,
          receiveId,
          failure.reported
        );
        await this.markMessageDeliveredSilently(envelope.id, options);
        return {
          outcome: { kind: 'denied', reason: receiveDenialReason(error as Error) },
          error: error as Error,
        };
      }
      if (isRetryableDecryptionError(error as Error)) {
        await this.sendRetryRequestInternal(inner, error as Error, family, receiveId, options);
      }
      throw error;
    }
    if (admitted === null) {
      return { outcome: { kind: 'refused', persisted: false, reason: 'capacity' } };
    }
    const record = await this._storage.getReceiveWork(workId);
    // The caller acknowledges only content that is stored.
    if (!record) throw new Error('The store did not commit the receive record');
    return { record };
  }

  /**
   * The `processed` outcome of a helper record that waits for completion.
   * With `onPersist`, the record completes when the callback resolves. A
   * callback that rejects leaves the record for a redelivery or for
   * `completeReceive`.
   */
  private async processedReceive(
    record: ReceiveWorkRecord,
    options: ProcessEnvelopeOptions | undefined
  ): Promise<ProcessedReceive> {
    const outcome: ProcessedReceive = {
      kind: 'processed',
      // The caller gets the content as its sender gave it.
      plaintext: this.contentAdapter.withoutGroupContext(record.plaintext!),
      messageId: record.messageId ?? record.workId,
      ...(record.groupId !== undefined && { groupId: extractGroupId(record.groupId) }),
    };
    if (options?.onPersist) {
      try {
        await options.onPersist(outcome);
      } catch (error) {
        this.logger.warn('The application failed to store received content', {
          category: 'E2EE',
          data: {
            messageId: outcome.messageId,
            behavior: 'RECEIVE_PERSIST_FAILED',
            error: (error as Error).message,
          },
        });
        return outcome;
      }
      await this.completeCallerRecord(record.workId);
    }
    return outcome;
  }

  /**
   * Complete one helper record that waits for completion. A record whose
   * revision changed is read again once.
   */
  private async completeCallerRecord(workId: string): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt++) {
      const record = await this._storage.getReceiveWork(workId);
      if (record?.origin !== 'caller' || record.stage !== 'awaiting-completion') return;
      if (await completeReceiveWork(this.ctx, record)) return;
    }
  }

  /** The application view of one stored receive. */
  private pendingReceiveOf(record: ReceiveWorkRecord): PendingReceive {
    const ready = record.stage === 'awaiting-completion';
    return {
      // A converted legacy record has no message ID. Its outcomes give the
      // record ID, as `completeReceive` matches.
      messageId: record.messageId ?? record.workId,
      stage: ready ? 'awaiting-completion' : 'decrypted',
      origin: record.origin,
      receivedAt: record.receivedAt,
      ...(record.senderUserId !== undefined && { senderId: record.senderUserId }),
      ...(record.senderDeviceId !== undefined && { senderDeviceId: record.senderDeviceId }),
      ...(record.groupId !== undefined && { groupId: extractGroupId(record.groupId) }),
      ...(ready &&
        record.plaintext !== undefined && {
          plaintext: this.contentAdapter.withoutGroupContext(record.plaintext),
        }),
      hookAttempts: record.hookAttempts ?? 0,
    };
  }

  /**
   * Process multiple incoming encrypted message envelopes.
   *
   * This is the preferred method for batch message processing. It handles:
   * 1. Sorting PreKeyMessages before ciphertexts (SESAME session convergence)
   * 2. Processing each envelope in order
   * 3. Collecting results/errors for caller to handle
   *
   * The sorting processes PreKeyMessages (which establish sessions)
   * before ciphertexts that depend on those sessions. SESAME Section 3.4
   * session convergence requires this when the client promotes archived sessions.
   *
   * @param envelopes - Array of encrypted message envelopes
   * @param options - Transport callbacks for background scenarios, and `onPersist`
   * @returns Array of results, each either the receive outcome or the error
   *
   * @example
   * ```typescript
   * const results = await signal.processIncomingEnvelopes(pendingMessages);
   * for (const result of results) {
   *   if ('outcome' in result) {
   *     handleReceiveOutcome(result.envelope, result.outcome);
   *   } else {
   *     handleDecryptionError(result.envelope, result.error);
   *   }
   * }
   * ```
   *
   * @see https://signal.org/docs/specifications/sesame/ Section 3.4
   */
  async processIncomingEnvelopes(
    envelopes: IncomingEnvelope[],
    options?: ProcessEnvelopeOptions
  ): Promise<
    Array<
      | { envelope: IncomingEnvelope; outcome: ReceiveOutcome }
      | { envelope: IncomingEnvelope; error: Error }
    >
  > {
    // Sort PreKeyMessages first - they establish sessions needed by subsequent ciphertexts
    // This is internal - callers do not need to know about SESAME session convergence
    const sorted = sortEnvelopesForDecryption(envelopes);

    const results: Array<
      | { envelope: IncomingEnvelope; outcome: ReceiveOutcome }
      | { envelope: IncomingEnvelope; error: Error }
    > = [];

    for (const envelope of sorted) {
      try {
        const outcome = await this.processIncomingEnvelope(envelope, options);
        results.push({ envelope, outcome });
      } catch (error) {
        results.push({ envelope, error: error as Error });
      }
    }

    return results;
  }

  /**
   * Receive a pulled batch through the subscription content handler.
   * The application must register onMessageDecrypted before calling this method.
   * Processed IDs are ready for transport acknowledgment. They include
   * each envelope that the client drops as a duplicate, and each null
   * message that the content adapter reports, which the client consumes
   * and never gives to onMessageDecrypted.
   *
   * The content reaches onMessageDecrypted in a later pass of the receive
   * queue, after this call returns. After `stop()`, the content waits for
   * the next start of the queue from `startRelaySubscription`, or for
   * `processPendingReceives`.
   */
  async receiveIncomingEnvelopes(envelopes: IncomingEnvelope[]): Promise<{
    processedMessageIds: string[];
    failedMessageIds: string[];
  }> {
    const { release, ...results } = await this.commitIncomingEnvelopes(envelopes);
    release();
    return results;
  }

  /**
   * @internal Commit a pulled batch as `receiveIncomingEnvelopes` does, and
   * keep each record held until `release` runs. A queue pass skips a held
   * record, so the hosted pull releases only after its acknowledgment
   * settles, and no content reaches the application before it. `release`
   * then wakes the queue.
   */
  async commitIncomingEnvelopes(envelopes: IncomingEnvelope[]): Promise<{
    processedMessageIds: string[];
    failedMessageIds: string[];
    release: () => void;
  }> {
    if (!this.hooks?.onMessageDecrypted) {
      throw new Error('Register onMessageDecrypted before receiving Relay messages');
    }
    const processedMessageIds: string[] = [];
    const failedMessageIds: string[] = [];
    const releases: Array<() => void> = [];
    const release = () => {
      for (const releaseOne of releases) releaseOne();
      this.receiveQueue.wake();
    };
    const context = { ...this.ctx, cipher: this.cipher, receiveQueue: this.receiveQueue };
    try {
      for (const envelope of sortEnvelopesForDecryption(envelopes)) {
        releases.push(
          this.receiveQueue.hold(
            await deliveredEnvelopeFingerprint(this.userId, this.deviceId, envelope)
          )
        );
        try {
          const processed = await RelaySubscriptionOps.processRelayMessage(
            context,
            this.relayEnvelopeOf(envelope),
            this.relaySubscriptionState,
            this.relaySubscriptionCallbacks(context),
            { ...this.relaySubscriptionConfig, acknowledgeFailures: false }
          );
          (processed ? processedMessageIds : failedMessageIds).push(envelope.id);
        } catch {
          failedMessageIds.push(envelope.id);
        }
      }
    } catch (error) {
      release();
      throw error;
    }
    return { processedMessageIds, failedMessageIds, release };
  }

  /**
   * Internal: Send SESAME retry request for failed decryption.
   *
   * Uses relay if available, otherwise falls back to options callback.
   * Called automatically by processIncomingEnvelope on retryable errors.
   *
   * @param envelope - The failed message envelope
   * @param error - The decryption error
   * @param family - The retry family of the delivered envelope
   * @param fingerprint - The fingerprint of the delivered envelope
   * @param options - Optional transport callbacks (for background without relay)
   */
  private async sendRetryRequestInternal(
    envelope: IncomingEnvelope,
    error: Error,
    family: RetryFamilyReceive,
    fingerprint: string | undefined,
    options?: ProcessEnvelopeOptions
  ): Promise<void> {
    return RetryOps.sendRetryRequestInternal(
      this.ctx as RetryOps.RetryContext,
      envelope,
      error,
      this.rateLimitState,
      { forcePreKeyRotation: () => this.regeneratePreKeysWithFreshIds() },
      this.retryConfig,
      family,
      fingerprint,
      options
    );
  }

  // ============================================================================
  // FILE ENCRYPTION/DECRYPTION (delegated to files.ts)
  // ============================================================================

  /**
   * Encrypt file blob with two-layer encryption
   *
   * Layer 1: Random symmetric key encrypts the file
   * Layer 2: Signal Protocol encrypts the symmetric key
   *
   * This allows efficient storage of large files with Signal Protocol key rotation.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param fileBlob - File data to encrypt
   * @param mimeType - Optional MIME type (defaults to fileBlob.type)
   * @returns Encrypted blob, key ID, and encrypted key
   */
  async encryptFile(
    remoteAddress: ProtocolAddress,
    fileBlob: Blob,
    mimeType?: string
  ): Promise<{
    encryptedBlob: Blob;
    keyId: string;
    encryptedKey: Ciphertext;
  }> {
    return FileOps.encryptFile(this.ctx, remoteAddress, fileBlob, mimeType);
  }

  /**
   * Decrypt file blob
   *
   * @param remoteAddress - Remote device's protocol address
   * @param encryptedBlob - Encrypted file data
   * @param encryptedKey - Encrypted symmetric key
   * @returns Decrypted file blob with correct MIME type
   */
  async decryptFile(
    remoteAddress: ProtocolAddress,
    encryptedBlob: Blob,
    encryptedKey: Ciphertext
  ): Promise<Blob> {
    return FileOps.decryptFile(this.ctx, remoteAddress, encryptedBlob, encryptedKey);
  }

  /**
   * Encrypt multiple files in batch
   *
   * More efficient than calling encryptFile() multiple times.
   * Each file gets its own encryption key for granular access control.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param files - Array of file blobs with optional MIME types
   * @returns Array of encrypted file results in the same order
   */
  async encryptFiles(
    remoteAddress: ProtocolAddress,
    files: Array<{ blob: Blob; mimeType?: string }>
  ): Promise<
    Array<{
      encryptedBlob: Blob;
      keyId: string;
      encryptedKey: Ciphertext;
    }>
  > {
    return FileOps.encryptFiles(this.ctx, remoteAddress, files);
  }

  /**
   * Decrypt multiple files in batch
   *
   * More efficient than calling decryptFile() multiple times.
   *
   * @param remoteAddress - Remote device's protocol address
   * @param files - Array of encrypted file data
   * @returns Array of decrypted file blobs in the same order
   */
  async decryptFiles(
    remoteAddress: ProtocolAddress,
    files: Array<{
      encryptedBlob: Blob;
      encryptedKey: Ciphertext;
    }>
  ): Promise<Blob[]> {
    return FileOps.decryptFiles(this.ctx, remoteAddress, files);
  }

  // ============================================================================
  // PRIMARY PUBLIC API
  // ============================================================================

  /**
   * Send encrypted content to a user or group
   *
   * This is the ONE way to send content. Handles:
   * - DataMessageInput: Structured proto content (serialized to protobuf)
   * - String content: Text or structured data (encoded to UTF-8 bytes)
   * - Uint8Array: Pre-serialized binary content (passed through)
   * - User recipients: Encrypts for all user's devices via SESAME
   * - Group recipients: Uses Sender Keys for O(1) encryption
   *
   * The client normalizes all inputs to Uint8Array before they reach the cipher layer.
   *
   * @param recipientId - User ID or group ID (groups use the package group ID prefix)
   * @param content - DataMessageInput, string, or Uint8Array to encrypt and send
   * @param options - Optional send options (isBinary for blob encryption, etc.)
   * @returns SendResult with messageId, timestamp, and device count
   *
   * @example
   * ```typescript
   * import { createGroupId } from '@open-e2ee/signal-protocol-sdk';
   *
   * // Send text message
   * await signal.send('bob', 'Hello!');
   *
   * // Send structured data
   * await signal.send('bob', { body: 'Hello!', timestamp: Date.now() });
   *
   * // Send binary attachment (two-layer encryption)
   * await signal.send('bob', photoBytes, { isBinary: true, mimeType: 'image/jpeg' });
   *
   * // Send to group (use createGroupId helper)
   * await signal.send(createGroupId('abc123'), 'Hello everyone!');
   * ```
   */
  async send(
    recipientId: string,
    content: DataMessageInput | string | Uint8Array,
    options?: SendOptions
  ): Promise<SendResult> {
    return this.sendWithContext(recipientId, content, options, this.ctx, undefined);
  }

  /**
   * Send with session callbacks whose hooks run through the given context.
   * The stop signal of relay work ends a wait for the recipient's lock.
   */
  private async sendWithContext(
    recipientId: string,
    content: DataMessageInput | string | Uint8Array,
    options: SendOptions | undefined,
    context: SignalProtocolClientContext,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    // Every send error carries the logical-send identifier, also an error
    // before the encryption, such as a failed content serialization.
    const clientMessageId = options?.clientMessageId ?? (await generateUuidV4());
    try {
      return await this.sendIdentified(
        recipientId,
        content,
        options,
        context,
        stopSignal,
        clientMessageId
      );
    } catch (error) {
      throw attachClientMessageId(error, clientMessageId);
    }
  }

  /** Send under a logical-send identifier that the caller already chose. */
  private async sendIdentified(
    recipientId: string,
    content: DataMessageInput | string | Uint8Array,
    options: SendOptions | undefined,
    context: SignalProtocolClientContext,
    stopSignal: AbortSignal | undefined,
    clientMessageId: string
  ): Promise<SendResult> {
    // Normalize all inputs to Uint8Array before calling cipher.encrypt()
    let plaintextBytes: Uint8Array;
    let clientTimestamp: number | undefined;
    // A new send checks an application-supplied timestamp once, here, before
    // the profile key work, the sweep, the intent write and any post. A send
    // that repeats a stored intent keeps the stored timestamp, which can be
    // outside the window, so a refused value passes only when a stored intent
    // for this identifier holds the same timestamp. The mark stops the inner
    // checks of this send.
    const applicationTimestamp = isDataMessage(content)
      ? (content.timestamp as number | undefined)
      : options?.timestamp;
    let timestampOrigin: SendTimestampOriginKind | undefined;
    if (applicationTimestamp == null) {
      if (isDataMessage(content)) timestampOrigin = 'sdk-clock';
    } else {
      try {
        checkNewSendTimestamp({ timestamp: applicationTimestamp });
        timestampOrigin = 'checked';
      } catch (error) {
        const existing = await getOutgoingMessageIntent(this._storage, clientMessageId);
        if (existing?.clientTimestamp !== applicationTimestamp) throw error;
      }
    }
    // A 1:1 send to a contact carries this account's profile key when an exchange is bound.
    const profileKeys =
      isGroupId(recipientId) || recipientId === this.userId ? undefined : profileKeyExchange(this);
    let profileKey: string | undefined;

    if (isDataMessage(content)) {
      // DataMessage path: build Content, set timestamp, serialize to protobuf (application send-pipeline ordering)
      const timestamp = (content.timestamp as number | undefined) ?? Date.now();
      clientTimestamp = timestamp;
      profileKey = await profileKeys?.outgoing();
      const dm: DataMessageInput = { ...content, timestamp, ...(profileKey && { profileKey }) };
      plaintextBytes = this.contentAdapter.serializeDataMessage(dm);
    } else if (typeof content === 'string') {
      await profileKeys?.offer(recipientId);
      plaintextBytes = new TextEncoder().encode(content);
    } else {
      await profileKeys?.offer(recipientId);
      plaintextBytes = content; // already Uint8Array
    }

    const contentHint = isGroupId(recipientId)
      ? this.groupContentHint(options?.contentHint, clientTimestamp !== undefined)
      : options?.contentHint;
    if (isGroupId(recipientId) && contentHint === ContentHint.Resendable) {
      await this.sweepResendableContentDaily();
    }
    // The public options type of the cipher has no mark, so the marked
    // options go in as a value of that type.
    const sendOptions: SendOptions & SendTimestampOrigin = {
      ...options,
      clientMessageId,
      ...(clientTimestamp !== undefined && { timestamp: clientTimestamp }),
      [SEND_TIMESTAMP_ORIGIN]: timestampOrigin,
      ...(contentHint !== undefined && { contentHint }),
    };
    const encrypt = (sendContext: SignalProtocolClientContext) =>
      this.cipher.encrypt(
        recipientId,
        plaintextBytes,
        sendOptions,
        this.sendSessionCallbacks(() => sendContext, stopSignal),
        stopSignal
      );
    // A receipt for this send waits until the send resolves.
    this.deliveries.beginSend(clientMessageId);
    let result: SendResult;
    try {
      // A group send sets up sessions while it holds the group's Sender Key lock.
      result = await (isGroupId(recipientId)
        ? this.withDeferredHooks(context, encrypt)
        : encrypt(context));
    } finally {
      this.deliveries.endSend(clientMessageId);
    }
    // A Relay that accepted a declared post without comparing it does not
    // change the result. The hook reports it once for the completed send.
    const protocolError = relayProtocolErrorOf(result);
    this.releaseDeliveries(clientMessageId);
    if (profileKey) await profileKeys?.delivered(recipientId, profileKey);
    if (protocolError) await callHook(context.hooks, 'onRelayProtocolError', protocolError);
    return clientTimestamp !== undefined ? { ...result, clientTimestamp } : result;
  }

  /** @see SignalProtocolClient.forgetSentContent */
  async forgetSentContent(clientMessageId: string): Promise<boolean> {
    return this.resendableContent.forget(clientMessageId);
  }

  /** @see SignalProtocolClient.getPendingRecipients */
  async getPendingRecipients(clientMessageId: string): Promise<SendLogDevice[]> {
    return this.resendableContent.pendingRecipients(clientMessageId);
  }

  async uploadAttachment(
    data: Uint8Array,
    options: SendOptions & { mimeType: string }
  ): Promise<import('./types').PreparedAttachmentUpload> {
    return this.cipher.uploadAttachment(data, options);
  }

  async downloadAttachment(
    attachment: MediaAttachmentPointer,
    options?: AttachmentTransferOptions
  ): Promise<import('./types').DownloadedAttachment> {
    if (!this.remoteObjectStore) {
      throw new EncryptionError(
        'Remote object storage not configured. Provide remoteObjectStore in DefaultSignalProtocolClient.create() config.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    return resolveMediaAttachment(attachment, {
      remoteObjectStore: this.remoteObjectStore,
      transfer: options?.transfer,
      retry: options?.retry,
      policy: options?.policy,
      signal: options?.signal,
      onProgress: options?.onProgress,
      onCheckpoint: options?.onCheckpoint,
      resume: options?.resume,
    });
  }

  async deleteRemoteAttachment(
    attachment: MediaAttachmentPointer,
    options?: Pick<AttachmentTransferOptions, 'signal' | 'onProgress'>
  ): Promise<void> {
    if (!this.remoteObjectStore) {
      throw new EncryptionError(
        'Remote object storage not configured. Provide remoteObjectStore in DefaultSignalProtocolClient.create() config.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    await deleteMediaAttachment(attachment, {
      remoteObjectStore: this.remoteObjectStore,
      signal: options?.signal,
      onProgress: options?.onProgress,
    });
  }

  /**
   * Generate safety number for verifying identity with another user
   *
   * Safety numbers allow users to verify they communicate with the
   * intended person and detect man-in-the-middle attacks.
   *
   * @param userId - The user ID to generate safety number for
   * @returns SafetyNumber with numeric code and fingerprint for QR
   *
   * @example
   * ```typescript
   * const safetyNum = await signal.verify('bob');
   *
   * // Show numeric code for phone/voice verification
   * console.log(`Safety Number: ${safetyNum.numeric}`);
   *
   * // Generate QR code from fingerprint
   * const qrCode = generateQR(safetyNum.fingerprint);
   * ```
   */
  async verify(
    userId: string,
    identityType: import('../keys').IdentityType = 'aci'
  ): Promise<SafetyNumber> {
    return SessionOps.verify(this.ctx, userId, identityType);
  }

  /** Confirm an authenticated comparison of the currently displayed tuple. */
  async confirmSafetyNumber(
    confirmation: import('./types').SafetyNumberConfirmation
  ): Promise<void> {
    await SessionOps.confirmSafetyNumber(this.ctx, confirmation);
  }

  /** Accept an authenticated composite-identity rotation and reset bound sessions. */
  async acceptIdentityRotation(
    userId: string,
    identity: import('../keys').CompositeIdentityV1,
    identityType: import('../keys').IdentityType = 'aci'
  ): Promise<import('../keys').ContactIdentityRecord> {
    return SessionOps.acceptIdentityRotation(this.ctx, userId, identity, identityType);
  }

  /**
   * Mark a message as read/delivered
   *
   * Signals to the server that the message was successfully received
   * and processed. Server may delete the message based on privacy settings.
   *
   * @param messageId - The message ID from SendResult
   *
   * @example
   * ```typescript
   * // After processing received message
   * await signal.markAsRead(envelope.id);
   * ```
   */
  async markAsRead(messageId: string): Promise<void> {
    if (!this.relay) {
      throw new EncryptionError(
        'Relay server not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    await this.relay.markDelivered(messageId);

    this.logger.debug('Message marked as read', {
      category: 'E2EE',
      data: { messageId },
    });
  }

  // ============================================================================
  // HOOK REGISTRATION (For post-construction hook registration)
  // ============================================================================

  /**
   * Register a hook callback after construction
   *
   * Enables dependency injection patterns where callers register hooks
   * after the DefaultSignalProtocolClient exists. ServicesProvider uses this
   * to wire up ContentManager's decryption hook.
   *
   * @param name - The hook name to register
   * @param callback - The callback function to invoke
   *
   * @example
   * ```typescript
   * // In ServicesProvider: wire up ContentManager after creation
   * const signal = await DefaultSignalProtocolClient.create(userId, { storage, relay });
   * const content = new ContentManager({ db, signal });
   *
   * signal.registerHook('onMessageDecrypted', content.getDecryptionHook());
   * signal.startRelaySubscription(); // Now safe to start
   * ```
   *
   * @see SignalProtocolClient.registerHook
   */
  registerHook<K extends keyof import('./event-hooks').SignalProtocolClientHooks>(
    name: K,
    callback: NonNullable<import('./event-hooks').SignalProtocolClientHooks[K]>
  ): void {
    assertHookName(name);
    this.hooks[name] = callback as SignalProtocolClientHooks[K];
    // Received content waits for this hook, or failed in the hook before.
    if (name === 'onMessageDecrypted') this.receiveQueue.retryFailedHooks();

    this.logger.debug('Hook registered', {
      category: 'E2EE',
      data: { hookName: name },
    });
  }

  // ============================================================================
  // RELAY SUBSCRIPTION (Auto-decrypt and notify ContentManager via hook)
  // ============================================================================

  /**
   * Start relay subscription for automatic message decryption
   *
   * When configured with both `relay` and `onMessageDecrypted` hook, DefaultSignalProtocolClient will:
   * 1. Subscribe to incoming envelopes from the relay
   * 2. Decrypt messages appropriately (pairwise vs group/sender key)
   * 3. Call onMessageDecrypted hook with DecryptedEnvelope (for ContentManager storage)
   * 4. Mark messages as delivered on the relay
   *
   * This enables ContentManager to store decrypted content in an encrypted SQLite
   * database without any knowledge of cryptography.
   *
   * Callers can run this manually after registering hooks via registerHook().
   * Called automatically by create() when relay + hook configured.
   * A call while stop() runs is refused and logged; start again after stop()
   * resolves.
   *
   * @see SignalProtocolClient.startRelaySubscription
   */
  public startRelaySubscription(): void {
    if (!this.relay) {
      this.logger.warn('Cannot start relay subscription: relay not configured', {
        category: 'E2EE',
      });
      return;
    }

    if (!this.hooks?.onMessageDecrypted) {
      this.logger.warn('Cannot start relay subscription: onMessageDecrypted hook required', {
        category: 'E2EE',
      });
      return;
    }

    // A start while stop() runs would outlive stop()
    if (this.stopping) {
      this.logger.debug('Relay subscription not started: stop() in progress', {
        category: 'E2EE',
      });
      return;
    }

    // Avoid duplicate subscriptions
    if (this.relayUnsubscribe) {
      this.logger.debug('Relay subscription already active', {
        category: 'E2EE',
      });
      return;
    }

    this.logger.debug('Starting relay subscription', {
      category: 'E2EE',
      data: { userId: this.userId, deviceId: this.deviceId },
    });
    this.startRetryRequests();

    this.relayUnsubscribe = this.relay.subscribe(
      this.userId,
      this.deviceId,
      (envelope) => {
        const handled = this.state.relayWork.run((work) => {
          const ctx = this.relayWorkContext(work);
          return RelaySubscriptionOps.handleRelayMessage(
            {
              ...ctx,
              cipher: this.cipher,
              receiveQueue: this.receiveQueue,
              stopSignal: work.stopSignal,
            },
            envelope,
            this.relaySubscriptionState,
            this.relaySubscriptionCallbacks(ctx, work.stopSignal),
            this.relaySubscriptionConfig
          );
        });
        handled.catch((error) => {
          // The relay delivers an envelope that it did not acknowledge again.
          this.logger.error('Failed to handle relay envelope', {
            category: 'E2EE',
            data: { envelopeId: envelope.id, error: (error as Error).message },
          });
        });
        // A relay that waits for the work, as the hosted transport does, ends
        // its batch and accepts an ephemeral message only after the work
        // settles, and pulls again after the work fails. A relay that does not
        // wait ignores the promise, and the handler above already holds its
        // failure.
        return handled;
      },
      {
        // Batching callbacks for notification coalescing
        onBatchStart: () => this.contentAdapter.setRelayBatching(true),
        onBatchEnd: () => this.contentAdapter.setRelayBatching(false),
      }
    );
  }

  /**
   * Delete the stale Sesame device records in the background. A removed
   * device record goes when its removal is older than `maxLatency`. The
   * receive queue runs it once in each run, after its resume. A failure is
   * logged, and the next run tries again.
   */
  private cleanupStaleDeviceRecords(): void {
    this.sesameManager.cleanupStaleRecords().catch((error: unknown) => {
      this.logger.warn('Stale device record cleanup failed', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    });
  }

  /**
   * Start the receive queue. After its resume, start the retry request
   * lifecycle.
   */
  private startRetryRequests(): void {
    void this.receiveQueue.start(() => this.startRetryLifecycle());
  }

  /**
   * Start the retry request scheduler and the resend job driver, each with a
   * pass in the background. Each relay transition to connected runs the
   * resend jobs again until stop().
   */
  private startRetryLifecycle(): void {
    void this.retryRequests.start();
    this.groupFetcher?.start().catch((error: unknown) => {
      this.logger.warn('The group fetcher failed to start', {
        category: 'E2EE',
        data: { behavior: 'GROUP_FETCH_START_FAILED', error: (error as Error).message },
      });
    });
    void this.resendJobs.start();
    const relay = this.relay;
    if (this.resendJobsOnConnect === undefined && relay) {
      this.resendJobsOnConnect = relay.subscribeRelayConnectionState((connection) => {
        if (connection.state === 'connected') void this.resendJobs.start();
      });
    }
  }

  /**
   * Stop the relay subscription
   *
   * Pauses message processing via the relay subscription without destroying
   * DefaultSignalProtocolClient state. startRelaySubscription() restarts the subscription.
   *
   * Use this when the app backgrounds to let the background task handle messages.
   * Resume when the app foregrounds for real-time message delivery.
   *
   * @see SignalProtocolClient.stopRelaySubscription
   */
  public stopRelaySubscription(): void {
    // Send the batched delivery receipts before unsubscribing. During the
    // hold, stop() sends the batches that wait at each of its flushes and
    // drops a batch made after its last flush.
    if (!this.relaySubscriptionState.receiptAccumulator.held) {
      this.flushPendingDeliveryReceipts();
    }

    if (this.relayUnsubscribe) {
      this.relayUnsubscribe();
      this.relayUnsubscribe = undefined;
      this.logger.debug('Relay subscription stopped', {
        category: 'E2EE',
        data: { userId: this.userId, deviceId: this.deviceId },
      });
    }
  }

  /**
   * Send delivery receipt to original sender (all devices)
   *
   * Per Signal Protocol, after successfully decrypting a message, the recipient
   * sends a delivery receipt back to the sender. The receipt identifies messages
   * by their timestamps (not sequence numbers).
   *
   * Multi-device: fans out to all known devices for the sender.
   *
   * @param recipientUserId - The sender's user ID (we are receipting TO them)
   * @param timestamps - Array of message timestamps that have been delivered
   * @param ctx - Client context, whose hooks run through the relay work of the send
   *
   * A failed send rejects and makes no retry of its own: the receive queue
   * keeps the receive in `receipt-due` and sends again. A send that the
   * Relay refused rejects with ReceiptSendTerminalError, and the queue
   * completes the receive with no receipt.
   */
  private async sendDeliveryReceipt(
    recipientUserId: string,
    timestamps: number[],
    ctx: SignalProtocolClientContext = this.receiptContext()
  ): Promise<void> {
    return MessageOps.sendReceipt(ctx, recipientUserId, timestamps, ReceiptType.DELIVERY, {
      report: true,
    });
  }

  /**
   * Send read receipt to original message sender (all devices)
   *
   * Called when the user views messages in a conversation.
   * Similar to delivery receipts but indicates message was actually read.
   *
   * Respects SDK privacy settings: if the configuration disables read receipts,
   * this method returns early without sending.
   *
   * @param recipientUserId - Original sender's user ID
   * @param timestamps - Server timestamps of the messages the user read
   */
  async sendReadReceipt(recipientUserId: string, timestamps: number[]): Promise<void> {
    // Check privacy setting at protocol layer
    const enabled = await this.contentAdapter.areReadReceiptsEnabled();
    if (!enabled) {
      this.logger.debug('Read receipts disabled by user preference', {
        category: 'E2EE',
      });
      return;
    }

    return this.sendReceipt(recipientUserId, timestamps, ReceiptType.READ);
  }

  /**
   * Send viewed receipt to original message sender (all devices).
   *
   * Uses the same privacy gate as read receipts.
   */
  async sendViewedReceipt(recipientUserId: string, timestamps: number[]): Promise<void> {
    const enabled = await this.contentAdapter.areReadReceiptsEnabled();
    if (!enabled) {
      this.logger.debug('Viewed receipts disabled by user preference', {
        category: 'E2EE',
      });
      return;
    }

    return this.sendReceipt(recipientUserId, timestamps, ReceiptType.VIEWED);
  }

  /**
   * Sync local read state to our other linked devices.
   *
   * Unlike read receipts, this is account-local multi-device state and should
   * happen regardless of the user's remote read-receipt privacy preference.
   */
  async syncReadToLinkedDevices(entries: ReadSyncEntryInput[]): Promise<void> {
    await this.cipher.sendReadSyncToLocalOtherDevices(entries);
  }

  /**
   * Sync a local view-once open event to our other linked devices.
   */
  async syncViewOnceOpenToLinkedDevices(entry: ViewOnceOpenSyncInput): Promise<void> {
    await this.cipher.sendViewOnceOpenSyncToLocalOtherDevices(entry);
  }

  /**
   * Sync a local media attachment delete event to our other linked devices.
   */
  async syncMediaAttachmentDeleteToLinkedDevices(
    entry: MediaAttachmentDeleteSyncInput
  ): Promise<void> {
    await this.cipher.sendMediaAttachmentDeleteSyncToLocalOtherDevices(entry);
  }

  /**
   * Sync local account-level communication/privacy configuration to our other linked devices.
   */
  async syncConfigurationToLinkedDevices(
    configuration: import('./content-adapter').ConfigurationSyncInput
  ): Promise<void> {
    await this.cipher.sendConfigurationSyncToLocalOtherDevices(configuration);
  }

  /**
   * Sync local username and username-link state to the account's other linked devices.
   *
   * Linked devices converge on the same username-link handle and entropy
   * without rotating it.
   */
  async syncUsernameStateToLinkedDevices(
    usernameState: import('./content-adapter').UsernameStateSyncInput
  ): Promise<void> {
    await this.cipher.sendUsernameStateSyncToLocalOtherDevices(usernameState);
  }

  /**
   * Sync learned recipient username metadata to the account's other linked devices.
   *
   * Remote usernames are transient metadata, but once one local device learns
   * them they should converge across the account's linked devices.
   */
  async syncRecipientUsernameToLinkedDevices(
    recipientUsername: RecipientUsernameSyncInput
  ): Promise<void> {
    await this.cipher.sendRecipientUsernameSyncToLocalOtherDevices(recipientUsername);
  }

  /**
   * Sync local safety-number verification state to our other linked devices.
   *
   * The client syncs only explicit `verified` and cleared-to-`default` states.
   * Key-conflict/untrusted state remains local and derived from identity-key
   * changes.
   */
  async syncVerificationStateToLinkedDevices(
    verificationState: import('./content-adapter').VerificationStateSyncInput
  ): Promise<void> {
    await this.cipher.sendVerificationStateSyncToLocalOtherDevices(verificationState);
  }

  /**
   * Sync task-notification acknowledgment state to our other linked devices.
   *
   * This is account-local notification state: if one device dismisses or acts
   * on a task reminder, the user's other devices should cancel their copies.
   */
  async syncTaskNotificationAckToLinkedDevices(
    input: Omit<import('./content-adapter').TaskNotificationAckSyncInput, 'acknowledgedOnDevice'>
  ): Promise<void> {
    await this.cipher.sendTaskNotificationAckSyncToLocalOtherDevices({
      ...input,
      acknowledgedOnDevice: this.deviceId,
    });
  }

  /**
   * Sync the current blocked-recipient snapshot to the account's other linked devices.
   *
   * The payload is a full snapshot, not a block/unblock delta.
   */
  async syncBlockedRecipientsToLinkedDevices(blocked: BlockedRecipientsSyncInput): Promise<void> {
    await this.cipher.sendBlockedRecipientsSyncToLocalOtherDevices(blocked);
  }

  /**
   * Send typing indicator to conversation recipient
   *
   * Delegates to MessageOps.sendTypingIndicator for implementation.
   */
  async sendTypingIndicator(
    recipientUserId: string,
    recipientDeviceId: number,
    conversationId: string,
    action: TypingAction,
    groupId?: string
  ): Promise<void> {
    return MessageOps.sendTypingIndicator(
      this.ctx,
      recipientUserId,
      recipientDeviceId,
      conversationId,
      action,
      groupId
    );
  }

  /**
   * Client context of a receipt send outside relay work, such as a read
   * receipt that the app sends. It carries the stop signal of the tracker,
   * so the next stop() clears the retry timer of the send. stop() does not
   * wait for the send.
   */
  private receiptContext(): SignalProtocolClientContext {
    return { ...this.ctx, stopSignal: this.state.relayWork.stopSignal };
  }

  /**
   * Internal method to send receipt (delivery or read)
   *
   * Delegates to MessageOps.sendReceipt for implementation. The context
   * carries the stop signal of the tracker, so the next stop() clears the
   * retry timer of the send.
   */
  private async sendReceipt(
    recipientUserId: string,
    timestamps: number[],
    type: ReceiptType,
    ctx: SignalProtocolClientContext = this.receiptContext()
  ): Promise<void> {
    return MessageOps.sendReceipt(ctx, recipientUserId, timestamps, type);
  }

  /**
   * Handle incoming delivery/read receipt and clean up MessageRecords
   *
   * Delegates to MessageOps.handleDeliveryReceipt for implementation.
   */
  private async handleDeliveryReceipt(
    envelope: Envelope,
    receipt: ParsedReceiptContent | null,
    ctx: SignalProtocolClientContext = this.ctx
  ): Promise<void> {
    return MessageOps.handleDeliveryReceipt(ctx, envelope, receipt);
  }

  /**
   * Handle incoming typing indicator
   *
   * Delegates to MessageOps.handleTypingIndicator for implementation.
   */
  private async handleTypingIndicator(
    envelope: Envelope,
    typing: ParsedTypingContent | null,
    ctx: SignalProtocolClientContext = this.ctx
  ): Promise<void> {
    return MessageOps.handleTypingIndicator(ctx, envelope, typing);
  }

  /**
   * Stop the Signal Protocol client and clean up resources
   *
   * Call this when the user logs out or the app shuts down.
   * It starts the send of each batched delivery receipt, once each, and
   * unsubscribes from the relay server. Then it waits for delivery receipt
   * sends, with their app hooks, until one receipt deadline 5 s after stop()
   * starts. It waits for each receipt send that is in progress when stop()
   * starts, except a send that an earlier stop() stopped, and for the sends
   * that it starts. A delivery that finishes during the wait batches its
   * receipt. At the end of each wait, stop() sends the batches that wait and
   * waits for those sends until the same deadline. It does this again while
   * the deadline is not past. stop() holds the receipt batches from its
   * first flush until it clears its tracking state. During the hold,
   * stopRelaySubscription() does not send them, and stop() drops a receipt
   * batched after its last flush. At the deadline it stops each receipt
   * send that is left: a send that waits in an app hook stops, and that
   * receipt is not sent. A send that is in its relay call at the deadline
   * is waited for, and that receipt can still be sent. It also
   * waits for the SDK work of the deliveries and retry requests in progress.
   * Then it cleans up any pending operations.
   *
   * Apart from the receipt wait, it does not wait for app hooks, so a hook
   * can await stop(). A hook of a delivery receipt send that awaits stop()
   * holds stop() until the receipt deadline. stop() does not wait for read
   * and viewed receipt sends. When a hook returns after stop(), the SDK drops
   * the work after the hook and writes nothing more. The relay delivers the
   * envelope again after the next start.
   *
   * A call to startRelaySubscription() while stop() runs is refused and
   * logged; start again after stop() resolves. A stop() call that overlaps a
   * running stop() waits for it and settles as it settles.
   *
   * @example
   * ```typescript
   * // On logout
   * await signal.stop();
   * ```
   */
  async stop(): Promise<void> {
    if (this.stopping) {
      // An overlapping call waits for the running stop() and settles as it
      // settles. No subscription can start during the run
      await this.stopping;
      return;
    }
    this.stopping = this.stopOnce();
    try {
      await this.stopping;
    } finally {
      this.stopping = undefined;
    }
  }

  /** The steps of one stop(). A stop() call that overlaps it waits for it. */
  private async stopOnce(): Promise<void> {
    // stop() sets this.stopping before step 1 runs. So a stop() call from a
    // step, such as from a relay connection state listener in step 2, waits
    // for this run and does not start a second run. A subscription start
    // from a step is refused
    await Promise.resolve();

    // 0. Stop the retry request scheduler, the resend job driver, the group
    // fetcher, and the receive queue, so no pass starts. Step 4 waits for a
    // pass in progress, as for other relay work
    this.retryRequests.stop();
    this.resendJobs.stop();
    this.groupFetcher?.stop();
    this.receiveQueue.stop();
    this.resendJobsOnConnect?.();
    this.resendJobsOnConnect = undefined;

    // 1. Start the receipt deadline, 5 s from now. Take the receipt sends in
    // progress, except a send that an earlier stop() stopped, and start the
    // send of the batched delivery receipts, once each, as relay work. Until
    // the end of step 6, a delivery that finishes batches its receipt with no
    // timer, and stopRelaySubscription() does not send it. Step 5 sends the
    // batches that wait at the end of each wait, again while the deadline is
    // not past. A receipt batched after its last flush is dropped in step 6
    const receiptDeadline = Date.now() + RelaySubscriptionOps.STOP_RECEIPT_FLUSH_MS;
    const receiptSends = [
      ...[...this.deliveryReceiptSends]
        .filter(([work]) => !work.stopSignal.aborted)
        .map(([, send]) => send),
      ...this.flushPendingDeliveryReceipts(),
    ];
    const receiptAccumulator = this.relaySubscriptionState.receiptAccumulator;
    receiptAccumulator.held = true;
    try {
      // 2. Stop relay subscription. Clear it before the call, so a call that
      // the unsubscribe makes does not unsubscribe it again. If the call
      // throws, put it back, so the next stop() calls it again
      const relayUnsubscribe = this.relayUnsubscribe;
      this.relayUnsubscribe = undefined;
      if (relayUnsubscribe) {
        try {
          relayUnsubscribe();
        } catch (error) {
          this.relayUnsubscribe ??= relayUnsubscribe;
          throw error;
        }
        this.logger.debug('Relay subscription stopped', { category: 'E2EE' });
      }

      // 3. Stop all relay work except the delivery receipt sends, then wait
      // for the receipt sends of step 1, with their app hooks, until the
      // receipt deadline. A delivery, a receive queue pass, or a retry request
      // whose app hook returns during the wait writes nothing more. The relay
      // delivers an unacknowledged envelope again after the next start, and
      // the receive queue runs a stored receive record again at the next
      // start. A receipt send is not stopped here, because the relay has the
      // acknowledgment of its messages and does not deliver them again
      if (receiptSends.length > 0) {
        this.state.relayWork.stopAllExcept(new Set(this.deliveryReceiptSends.keys()));
        await this.waitForStopReceiptSends(receiptSends, receiptDeadline - Date.now());
      }

      // 4. Stop the relay work in progress and wait for its SDK work. Work
      // that waits in an app hook is not awaited. It writes nothing after
      // the hook, and the relay delivers it again after the next start. So a
      // receipt send that waits in an app hook after the deadline stops, and
      // that receipt is not sent. A receipt send that is still in its relay
      // call is waited for, and that receipt can still be sent
      await this.state.relayWork.settle();

      // 5. A delivery can finish during steps 3, 4, and 5, and the relay does
      // not deliver it again. A delivery that waits for the Relay reply to its
      // acknowledgment gets no reply after the unsubscribe, so release it to
      // its E2EE receipt. Send the receipts that such deliveries batched,
      // wait for them until the same receipt deadline, and stop what is left
      // as step 4 does. Do this again while a batch waits and the deadline
      // is not past
      const receiptJoin = this.relay === undefined ? undefined : relayReceiptJoinOf(this.relay);
      do {
        receiptJoin?.release();
        const lateReceiptSends = this.flushPendingDeliveryReceipts();
        if (lateReceiptSends.length === 0) break;
        await this.waitForStopReceiptSends(lateReceiptSends, receiptDeadline - Date.now());
        await this.state.relayWork.settle();
      } while (Date.now() < receiptDeadline);

      // 6. Release a delivery that started to wait for its reply after the
      // last release, so that no reply timer batches its receipt after
      // stop(). Then clear internal tracking state via state manager. This
      // drops the receipts batched after the last flush of step 5, which is
      // the last flush before the deadline or the first flush after step 4.
      // Then the hold ends, and new batches set their timers again
      receiptJoin?.release();
      this.state.clearForStop();
    } finally {
      receiptAccumulator.held = false;
    }

    // 7. Cleanup expired Sesame sessions
    try {
      await this.sesameManager.cleanupExpiredSessions();
    } catch (error) {
      this.logger.warn('Error cleaning up Sesame sessions', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }

    // 8. Cleanup expired resendable content (SESAME spec §6.2 and the send log)
    try {
      const deleted = await this.resendableContent.sweep();
      if (deleted.messageRecords > 0 || deleted.sendLogEntries > 0) {
        this.logger.debug('Cleaned up expired resendable content', {
          category: 'E2EE',
          data: deleted,
        });
      }
    } catch (error) {
      // Log but do not fail stop
      this.logger.warn('Error cleaning up resendable content', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }

    this.logger.debug('DefaultSignalProtocolClient stopped', {
      category: 'E2EE',
      data: { userId: this.userId, deviceId: this.deviceId },
    });
  }

  /**
   * Receive and decrypt message from another device (multi-device support)
   *
   * Implements session convergence per SESAME spec.
   *
   * @param message - The encrypted Sesame message envelope
   * @returns Decrypted plaintext
   */
  async receive(message: SesameMessage): Promise<string> {
    return this.cipher.decryptPairwise(message);
  }

  /**
   * Get Sesame session statistics (for debugging)
   *
   * Returns information about users, devices, and sessions.
   *
   * @returns Session statistics
   */
  async getSesameStats(): Promise<SesameStats> {
    return this.sesameManager.getStats();
  }

  /**
   * Cleanup expired Sesame sessions
   *
   * Removes inactive sessions that are older than the configured TTL.
   * Call this periodically (e.g., daily) to prevent database bloat.
   *
   * @returns Number of sessions cleaned up
   */
  async cleanupExpiredSesameSessions(): Promise<number> {
    const cleaned = await this.sesameManager.cleanupExpiredSessions();
    this.logger.debug('Expired Sesame sessions cleaned up', {
      category: 'E2EE',
      data: { count: cleaned },
    });
    return cleaned;
  }

  // ============================================================================
  // KEY ROTATION (delegated to key-rotation.ts)
  // ============================================================================

  /**
   * Rotate the device's prekeys in one publication.
   *
   * One inventory read decides whether the EC signed prekey, the KEM
   * last-resort prekey, or a one-time prekey batch is due. Signed keys rotate
   * once they are older than the configured refresh interval
   * ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default). Nothing due
   * costs one read and no publication, so it is safe to call often.
   *
   * @returns Which keys the rotation published, and one error per failed identity type
   */
  async rotatePreKeys(): Promise<PreKeyRotationResult> {
    return KeyRotationOps.rotatePreKeys(this.ctx);
  }

  // ============================================================================
  // GROUP MESSAGING (Sender Keys)
  // ============================================================================

  /**
   * Create a new sender key for group messaging
   *
   * Call this when joining a group or when the group needs key rotation.
   * Distribute the returned message to all group members via pairwise sessions.
   *
   * @param groupId - Unique identifier for the group
   * @returns Distribution message to share with group members
   *
   * @example
   * ```typescript
   * // Create sender key when joining a group
   * const { distributionMessage } = await signal.createGroupSenderKey('group-123');
   *
   * // Distribute to all members via pairwise encryption
   * for (const member of groupMembers) {
   *   const encrypted = await signal.encryptMessage(member.address, JSON.stringify(distributionMessage));
   *   await sendToMember(member, encrypted);
   * }
   * ```
   */
  async createGroupSenderKey(groupId: string): Promise<{
    senderKeyId: string;
    distributionMessage: SenderKeyDistributionMessage;
  }> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.createGroupSenderKey(this.ctx, this.senderKeyManager, rawGroupId)
    );
  }

  /**
   * Process a sender key distribution message from another group member
   *
   * Call this when receiving a sender key distribution message from a group member.
   * After processing, you can decrypt messages from that member.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param message - Distribution message containing the sender key
   *
   * @example
   * ```typescript
   * // Receive and process distribution message
   * const distributionMessage = JSON.parse(decryptedContent);
   * await signal.processGroupSenderKeyDistribution(
   *   'group-123',
   *   senderId,
   *   senderDeviceId,
   *   distributionMessage
   * );
   * ```
   */
  async processGroupSenderKeyDistribution(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    message: SenderKeyDistributionMessage
  ): Promise<void> {
    // Signal installs a distribution from an authenticated session with no
    // group check. The key decrypts nothing until group content that names
    // it passes the group checks.
    return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      return GroupOps.processSenderKeyDistribution(
        this.ctx, this.senderKeyManager, rawGroupId, senderId, senderDeviceId, message
      );
    });
  }

  /**
   * Encrypt a message for group using sender key (O(1) encryption)
   *
   * After creating your sender key and distributing it to members,
   * use this to encrypt messages. All group members can decrypt
   * the same ciphertext, making it efficient for large groups.
   *
   * @param groupId - Group identifier
   * @param plaintext - Message to encrypt
   * @returns Framed SenderKeyMessage bytes
   *
   * @example
   * ```typescript
   * // Encrypt once, send to all members
   * const encrypted = await signal.encryptGroupMessage('group-123', 'Hello everyone!');
   *
   * // Broadcast same ciphertext to all members
   * for (const member of groupMembers) {
   *   await sendToMember(member, encrypted);
   * }
   * ```
   */
  async encryptGroupMessage(groupId: string, plaintext: string): Promise<Uint8Array> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.encryptGroupMessage(
        this.ctx,
        this.senderKeyManager,
        rawGroupId,
        plaintext,
        this.groupManager
          ? (candidateGroupId) => this.groupManager!.assertGroupSendAllowed(candidateGroupId)
          : undefined
      )
    );
  }

  /**
   * Decrypt a group message from a sender
   *
   * Use this to decrypt messages from other group members.
   * You must process the sender's distribution message first.
   *
   * The message passes the group decision of `processIncomingEnvelope`.
   * Content whose group state must update first stays stored, and a later
   * call with the same message decides it with no second decrypt.
   *
   * @deprecated Use `processIncomingEnvelope`, which returns a receive
   *   outcome and keeps the content until the application completes the
   *   receive. This method completes the receive before it returns, so a
   *   plaintext that the application loses is gone.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param framedMessage - Framed SenderKeyMessage bytes
   * @returns Decrypted plaintext
   * @throws GroupReceiveUnavailableError when the group state of the content
   *   is not current. Its `messageId` names the stored receive. Call again
   *   later with the same message.
   * @throws GroupReceiveRefusedError when the client refuses the content
   * @throws EncryptionError MESSAGE_DUPLICATE for a message that this client
   *   processed, or that carries no content, and STORAGE_QUOTA_EXCEEDED when
   *   the receive queue has no room
   *
   * @example
   * ```typescript
   * const plaintext = await signal.decryptGroupMessage(
   *   'group-123',
   *   senderId,
   *   senderDeviceId,
   *   encryptedMessage
   * );
   * console.log('Message:', plaintext);
   * ```
   */
  async decryptGroupMessage(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    framedMessage: Uint8Array
  ): Promise<string> {
    // The message has no envelope ID, so its receive record ID binds the
    // sender and the framed bytes.
    const ciphertext = bytesToBase64(framedMessage);
    const workId = await deliveredEnvelopeFingerprint(this.userId, this.deviceId, {
      senderUserId: senderId,
      senderDeviceId,
      messageType: 'sender_key',
      ciphertext,
    });
    // A concurrent call with the same message waits here, and then reads
    // the record that the first call left, as a later call does.
    return withKeyedLock(groupMessageReceiveLocks, this._storage, workId, async () => {
      const { outcome, error } = await this.receiveForCaller(
        {
          id: '',
          senderUserId: senderId,
          senderDeviceId,
          ciphertext,
          timestamp: Date.now(),
          messageType: 'sender_key',
        },
        undefined,
        { groupId, workId, framed: framedMessage }
      );
      switch (outcome.kind) {
        case 'processed':
          await this.completeCallerRecord(workId);
          return outcome.plaintext;
        case 'pending':
        case 'denied':
          if (error) throw error;
          break;
        case 'refused':
          throw new EncryptionError(
            'The receive queue has no room for this group message',
            EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED,
            { senderId }
          );
        default:
          break;
      }
      throw new EncryptionError(
        'This group message gives no content',
        EncryptionErrorCode.MESSAGE_DUPLICATE,
        { senderId }
      );
    });
  }

  /**
   * Rotate sender key for a group (forward secrecy on membership changes).
   *
   * ## When to Call
   *
   * Per Signal Protocol specification, rotate sender keys on **membership changes**:
   *
   * | Event | Action |
   * |-------|--------|
   * | Member REMOVED | **ALL members** must rotate (forward secrecy) |
   * | Member ADDED | Distribute current key to new member (no rotation needed) |
   * | Group metadata changed | Rotate recommended |
   *
   * **Important**: The reference implementation does NOT use periodic or message-count-based rotation.
   * Only rotate when membership changes to maintain forward secrecy.
   *
   * ## Why Rotate on Member Removal?
   *
   * After the group removes a member, they still hold the old sender key and could decrypt
   * future messages if nothing rotates the key. ALL remaining members must generate
   * new sender keys to prevent the removed member from reading future messages.
   *
   * @param groupId - Group identifier
   * @returns New distribution message to share with remaining members
   *
   * @example
   * ```typescript
   * // When removing a member from a group
   * async function onMemberRemoved(groupId: string, remainingMembers: Member[]) {
   *   // Rotate our sender key (forward secrecy)
   *   const { distributionMessage } = await signal.rotateGroupSenderKey(groupId);
   *
   *   // Distribute new key to remaining members via pairwise encryption
   *   for (const member of remainingMembers) {
   *     const encrypted = await signal.encryptMessage(
   *       member.address,
   *       JSON.stringify(distributionMessage)
   *     );
   *     await sendToMember(member, encrypted);
   *   }
   * }
   *
   * // When adding a member - no rotation needed, just distribute current key
   * async function onMemberAdded(groupId: string, newMember: Member) {
   *   const { distributionMessage } = await signal.createGroupSenderKey(groupId);
   *   // Or get existing: signal.getGroupSenderKeyDistribution(groupId)
   *   const encrypted = await signal.encryptMessage(
   *     newMember.address,
   *     JSON.stringify(distributionMessage)
   *   );
   *   await sendToMember(newMember, encrypted);
   * }
   * ```
   *
   * @see handleGroupMembershipChange - Helper method for common membership patterns
   */
  async rotateGroupSenderKey(groupId: string): Promise<{
    senderKeyId: string;
    distributionMessage: SenderKeyDistributionMessage;
  }> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.rotateGroupSenderKey(
        this.ctx, this.senderKeyManager, rawGroupId, this.config.onGroupSenderKeyRotated
      )
    );
  }

  /**
   * Delete sender key when leaving a group
   *
   * @param groupId - Group identifier
   */
  async deleteGroupSenderKey(groupId: string): Promise<void> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.deleteGroupSenderKey(this.ctx, this.senderKeyManager, rawGroupId)
    );
  }

  /**
   * Check if we have a sender key for a group
   *
   * @param groupId - Group identifier
   * @returns True if sender key exists for this device
   */
  async hasGroupSenderKey(groupId: string): Promise<boolean> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.hasGroupSenderKey(this.ctx, rawGroupId)
    );
  }

  /**
   * Get the current sender key distribution message for a group
   *
   * If no sender key exists, returns null. Use createGroupSenderKey() first.
   *
   * @param groupId - Group identifier
   * @returns Distribution message or null if no key exists
   */
  async getGroupSenderKeyDistribution(
    groupId: string
  ): Promise<SenderKeyDistributionMessage | null> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      GroupOps.getGroupSenderKeyDistribution(this.ctx, rawGroupId)
    );
  }

  /**
   * Distribute sender key to a specific user via pairwise encryption.
   *
   * Distribution messages travel through authenticated, encrypted
   * pairwise channels.
   *
   * This method:
   * 1. Gets or creates sender key for this group
   * 2. Encrypts the distribution message using pairwise Signal Protocol
   * 3. Sends via SESAME to all of the recipient's devices
   *
   * @param groupId - Group identifier
   * @param recipientUserId - Recipient user ID to distribute key to
   *
   * @example
   * ```typescript
   * // Distribute key to a specific user
   * await signal.distributeSenderKeyToUser('group-123', 'bob');
   * ```
   */
  async distributeSenderKeyToUser(groupId: string, recipientUserId: string): Promise<void> {
    if (recipientUserId === this.userId) return;
    return this.withDeferredHooks(this.ctx, (context) =>
      this.groupSenderKeys.run(groupId, async (rawGroupId) => {
        const distribution = await this.getOrCreateSenderKeyDistribution(rawGroupId);
        await this.sendSenderKeyDistribution(rawGroupId, recipientUserId, distribution, context);
      })
    );
  }

  /** Called only while this client holds the group's Sender Key operation. */
  private async getOrCreateSenderKeyDistribution(groupId: string): Promise<SenderKeyDistributionMessage> {
    const distribution = await GroupOps.getGroupSenderKeyDistribution(this.ctx, groupId);
    if (distribution) return distribution;
    return (await GroupOps.createGroupSenderKey(this.ctx, this.senderKeyManager, groupId)).distributionMessage;
  }

  private async sendSenderKeyDistribution(
    groupId: string,
    recipientUserId: string,
    distribution: SenderKeyDistributionMessage,
    context: SignalProtocolClientContext
  ): Promise<void> {
    const payload = this.contentAdapter.serializeSenderKeyDistributionText(groupId, distribution);
    await this.sendWithContext(recipientUserId, payload, undefined, context, undefined);
    this.logger.debug('Distributed sender key to user', {
      category: 'E2EE',
      data: { groupId, recipientUserId, generation: distribution.generation },
    });
  }

  /**
   * Distribute sender key to all group members.
   *
   * Called after group creation or after key rotation.
   * Skips self and sends to all other members via pairwise encryption.
   *
   * @param groupId - Group identifier
   * @param memberUserIds - Array of all member user IDs
   *
   * @example
   * ```typescript
   * // After creating a group
   * const memberIds = ['alice', 'bob', 'charlie'];
   * await signal.distributeGroupSenderKey('group-123', memberIds);
   * ```
   */
  async distributeGroupSenderKey(groupId: string, memberUserIds: string[]): Promise<void> {
    const recipients = memberUserIds.filter((id) => id !== this.userId);
    if (recipients.length === 0) return;
    return this.withDeferredHooks(this.ctx, (context) =>
      this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      const distribution = await this.getOrCreateSenderKeyDistribution(rawGroupId);
      // Distribute to each member
      const results = await Promise.allSettled(
        recipients.map((userId) =>
          this.sendSenderKeyDistribution(rawGroupId, userId, distribution, context)
        )
      );

      // Count successes and failures
      const succeeded = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.filter((r) => r.status === 'rejected').length;

      this.logger.debug('Distributed sender key to group', {
        category: 'E2EE',
        data: { groupId: rawGroupId, succeeded, failed, total: recipients.length },
      });

      // If all failed, throw an error
      if (failed === recipients.length) {
        throw new EncryptionError(
          `Failed to distribute sender key to any group members`,
          EncryptionErrorCode.ENCRYPTION_FAILED
        );
      }
    })
    );
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Clean up expired message keys for a session
   *
   * Signal Protocol Section 8.4 recommends deleting message keys older than
   * one week to avoid excessive storage. This method explicitly triggers cleanup.
   *
   * Note: Cleanup also happens automatically during encrypt/decrypt operations.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @returns true if cleanup succeeded, false otherwise
   */
  async cleanupExpiredKeys(remoteAddress: ProtocolAddress): Promise<boolean> {
    return SessionOps.cleanupExpiredKeys(this.ctx, remoteAddress);
  }

  /**
   * Get encryption statistics
   *
   * @returns Statistics about sessions, keys, and usage
   */
  async getStats(): Promise<{
    hasIdentityKey: boolean;
    sessionCount: number;
    oneTimePreKeysCount: number;
  }> {
    return SessionOps.getStats(this.ctx);
  }

  /**
   * Get health status for encryption sessions with a specific user.
   *
   * Delegates to SessionOps.getSessionHealth for implementation.
   */
  async getSessionHealth(userId: string): Promise<import('./types').SessionHealthResult> {
    return SessionOps.getSessionHealth(this.ctx, userId);
  }

  /**
   * Check prekey status and trigger warning if running low
   *
   * Returns the current prekey count and whether the client needs to replenish.
   * If config supplies an `onPreKeyLow` callback, the client calls it when
   * the count drops below the threshold.
   *
   * @returns Prekey status with remaining count and replenishment flag
   *
   * @example
   * ```typescript
   * const status = await signal.checkPreKeyStatus();
   * if (status.needsReplenishment) {
   *   // Generate and upload more prekeys
   *   await backend.replenishPrekeys(userId);
   * }
   * ```
   */
  async checkPreKeyStatus(): Promise<PreKeyOps.PreKeyStatusResult> {
    return PreKeyOps.checkPreKeyStatus(
      this.ctx,
      this.config.preKeyLowThreshold ?? 50,
      this.config.onPreKeyLow
    );
  }

  /**
   * Clear all encryption data
   *
   * WARNING: This permanently deletes all keys and sessions.
   * Use only for local development or when resetting the app.
   */
  async clearAllData(): Promise<void> {
    await this._storage.clearAllKeys();
    this.logger.warn('All encryption data cleared', {
      category: 'E2EE',
      data: { userId: this.userId },
    });
  }

  /**
   * Get statistics for a group sender key.
   *
   * Useful for debugging and monitoring group messaging health.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @returns Stats including chain position, generation, and skipped keys count
   *
   * @example
   * ```typescript
   * const stats = await signal.getGroupSenderKeyStats('group-123', 'alice', 1);
   * console.log(`Chain at ${stats.chainIndex}, gen ${stats.generation}`);
   * console.log(`${stats.skippedKeysCount} skipped keys stored`);
   * ```
   */
  async getGroupSenderKeyStats(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<{
    chainIndex: number;
    generation: number;
    skippedKeysCount: number;
  }> {
    return this.groupSenderKeys.run(groupId, (rawGroupId) =>
      this.senderKeyManager.getStats(rawGroupId, senderId, senderDeviceId)
    );
  }

  /**
   * Handle group membership change with appropriate sender key actions.
   *
   * This convenience method applies the sender-key lifecycle for membership
   * changes:
   * - Member removed: Rotate sender key (forward secrecy)
   * - Member added: No rotation needed (just distribute current key)
   * - Metadata changed: Rotate recommended
   *
   * @param groupId - Group identifier
   * @param change - Type of membership change
   * @returns Distribution message if rotation occurred, for sending to members
   *
   * @example
   * ```typescript
   * // When a member is removed
   * const result = await signal.handleGroupMembershipChange(
   *   'group-123',
   *   'member_removed'
   * );
   *
   * if (result.rotated) {
   *   // Distribute new key to remaining members
   *   for (const member of remainingMembers) {
   *     const encrypted = await signal.encryptMessage(
   *       member.address,
   *       JSON.stringify(result.distributionMessage)
   *     );
   *     await sendToMember(member, encrypted);
   *   }
   * }
   * ```
   */
  async handleGroupMembershipChange(
    groupId: string,
    change: 'member_added' | 'member_removed' | 'metadata_changed'
  ): Promise<{
    rotated: boolean;
    distributionMessage?: SenderKeyDistributionMessage;
  }> {
    if (change === 'member_removed' || change === 'metadata_changed') {
      // Per the Signal Protocol sender-key model: rotate on removal or metadata
      // change for forward secrecy.
      const { distributionMessage } = await this.rotateGroupSenderKey(groupId);
      return { rotated: true, distributionMessage };
    }

    // member_added: no rotation needed, just distribute current key
    return { rotated: false };
  }

  // ============================================================================
  // GROUP STATE (Signal Private Group System)
  // ============================================================================

  /**
   * Create a new group.
   */
  async createGroup(
    creatorAci: Uint8Array,
    creatorProfileKey: Uint8Array,
    members: GroupMemberInput[],
    title: string,
    options?: {
      description?: string;
      accessControl?: Partial<AccessControl>;
      avatarUrl?: string;
      disappearingMessagesDuration?: number;
    }
  ): Promise<{ groupId: GroupId; masterKey: Uint8Array }> {
    return GroupOps.createGroup(
      this.ctx,
      await this.groups,
      creatorAci,
      creatorProfileKey,
      members,
      title,
      options
    );
  }

  /**
   * Get decrypted group state (from cache or server).
   */
  async getGroupState(groupId: GroupId): Promise<DecryptedGroup> {
    return GroupOps.getGroupState(this.ctx, await this.groups, groupId);
  }

  /**
   * Get the init status of a group on this device.
   *
   * @returns The status, or null when this device has no record of the group
   * @throws {EncryptionError} When the client has no groups config
   */
  async getGroupInitStatus(groupId: GroupId): Promise<GroupInitStatus | null> {
    if (!this.groupStore) {
      throw new EncryptionError(
        'Groups not configured. Provide groups config to DefaultSignalProtocolClient.create().',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    return readGroupInitStatus(this.groupStore, extractGroupId(groupId));
  }

  /**
   * Sync group state from server.
   */
  async syncGroup(groupId: GroupId): Promise<DecryptedGroup> {
    // A manual sync joins the receive fetch of the group, as one fetcher
    // owns each group's server work.
    const fetcher = this.groupFetcher;
    return GroupOps.syncGroup(
      this.ctx,
      fetcher
        ? { syncGroup: (id: GroupId) => fetcher.sync(extractGroupId(id)) }
        : await this.groups,
      groupId
    );
  }

  /**
   * Add a member to a group.
   */
  async addGroupMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    member: GroupMemberInput
  ): Promise<void> {
    return GroupOps.addGroupMember(this.ctx, await this.groups, groupId, editorAci, member);
  }

  /** Accept this client's pending profile-key invitation. */
  async acceptGroupMemberInvitation(groupId: GroupId): Promise<void> {
    return GroupOps.acceptGroupMemberInvitation(this.ctx, await this.groups, groupId);
  }

  /**
   * Decline this account's ACI- or PNI-keyed pending invitation.
   */
  async declineGroupMemberInvitation(
    groupId: GroupId,
    identity: 'aci' | 'pni' = 'aci'
  ): Promise<void> {
    return GroupOps.declineGroupMemberInvitation(this.ctx, await this.groups, groupId, identity);
  }

  /**
   * Remove a member from a group. Triggers sender key rotation.
   */
  async removeGroupMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    targetAci: Uint8Array
  ): Promise<void> {
    return GroupOps.removeGroupMember(this.ctx, await this.groups, groupId, editorAci, targetAci);
  }

  /**
   * Leave a group.
   */
  async leaveGroup(groupId: GroupId, userAci: Uint8Array): Promise<void> {
    return GroupOps.leaveGroup(this.ctx, await this.groups, groupId, userAci);
  }

  /**
   * Update a group's title.
   */
  async updateGroupTitle(groupId: GroupId, editorAci: Uint8Array, title: string): Promise<void> {
    return GroupOps.updateGroupTitle(this.ctx, await this.groups, groupId, editorAci, title);
  }

  /**
   * Update a group's description.
   */
  async updateGroupDescription(
    groupId: GroupId,
    editorAci: Uint8Array,
    description: string
  ): Promise<void> {
    return GroupOps.updateGroupDescription(this.ctx, await this.groups, groupId, editorAci, description);
  }

  /**
   * Update a group's access control.
   */
  async updateGroupAccessControl(
    groupId: GroupId,
    editorAci: Uint8Array,
    updates: Partial<AccessControl>
  ): Promise<void> {
    return GroupOps.updateGroupAccessControl(this.ctx, await this.groups, groupId, editorAci, updates);
  }

  /**
   * Create an invite link for a group.
   */
  async createGroupInviteLink(groupId: GroupId, editorAci: Uint8Array): Promise<string> {
    return GroupOps.createGroupInviteLink(this.ctx, await this.groups, groupId, editorAci);
  }

  /**
   * Join a group via invite link.
   */
  async joinGroupViaInviteLink(
    url: string,
    userAci: Uint8Array,
    userProfileKey: Uint8Array
  ): Promise<{ groupId: GroupId; status: 'joined' | 'pending_approval' }> {
    return GroupOps.joinGroupViaInviteLink(this.ctx, await this.groups, url, userAci, userProfileKey);
  }

  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================

  /**
   * Sanitize config for logging (remove sensitive data)
   */
  private sanitizeConfig(config: SignalProtocolClientConfig): Record<string, unknown> {
    return {
      hasStorage: !!config.storage,
      hasProtocolManager: !!config.protocolManager,
      enableDebugLogging: config.enableDebugLogging,
      throwDetailedErrors: config.throwDetailedErrors,
    };
  }
}
