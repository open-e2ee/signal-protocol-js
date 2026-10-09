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
  SignalProtocolClient,
  SignalProtocolLocalStore,
  SignalProtocolManager,
  Base64,
} from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
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
  type DeliveredEvent,
  type SignalProtocolClientHooks,
} from './event-hooks';
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
  type ParsedTypingContent,
  type ReadSyncEntryInput,
  type RecipientUsernameSyncInput,
  type SignalProtocolContentAdapter,
  type ViewOnceOpenSyncInput,
} from './content-adapter';
// Note: group utilities (isGroupId, extractGroupId, createGroupId) are used by SignalProtocolServiceCipher
import { isGroupId } from '../internal/groups';
import { GroupSenderKeyOperations } from './group-sender-key-operations';
import { createGroupReceiveAuthorizer, type GroupReceiveAuthorizer } from './group-receive-authorization';
import { profileKeyExchange } from './profile-key-exchange';
import {
  SignalProtocolServiceCipher,
  sortEnvelopesForDecryption,
  type SendSessionCallbacks,
} from './signal-service-cipher';
import { establishMultiDeviceSessions } from '../internal/sesame/device-registry';
import { isRetryableDecryptionError } from './retry-utils';
import { envelopeTypeForContent, unsealMessage } from './sealed-sender';
import { MESSAGE_RECORD_TTL_MS } from './constants';
import type { DataMessageInput } from './types';

// Import operation modules
import type {
  AttachmentTransferOptions,
  SignalProtocolClientContext,
  SendOptions,
  SendResult,
  SafetyNumber,
  IncomingEnvelope,
  ProcessEnvelopeOptions,
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
import { deliveredEnvelopeFingerprint } from '../local/store/received-content';
import * as RelaySubscriptionOps from './relay-subscription';
import { relayReceiptJoinOf } from './relay-receipt-join';
import { SignalProtocolClientState, SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
import {
  clientRelayFanOut,
  rethrowRelayWorkStopped,
  RelayWorkStopped,
  type RelayWork,
} from './relay-work';
import type { BoundedFanOut } from '../utils/bounded-fan-out';
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
  private groupReceiveAuthorizer?: GroupReceiveAuthorizer;

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

    // Dependency injection: Use provided protocol manager or create new one with our storage and protocol strategy
    this.manager =
      config.protocolManager ??
      new DefaultSignalProtocolManager(this._storage, config.protocolStrategy, this.logger);

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

    // Wire up MessageRecord storage for retry request support (SESAME spec §6.2)
    this.sesameManager.setMessageRecordStore(this._storage);

    // Initialize Sender Key manager for group messaging
    this.senderKeyManager = new SenderKeyManager(this._storage, config?.senderKeys, this.logger);
    this.groupSenderKeys = new GroupSenderKeyOperations(this._storage, userId, deviceId);

    // Initialize the group manager if configured
    if (config?.groups) {
      const groupConfig = config.groups;
      this.groupStore = config.groups.store ?? new SignalProtocolGroupStateStore(this._storage);
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
                this.config.onGroupSenderKeyRotated,
                { distributionPending: true }
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
      this.groupReceiveAuthorizer = createGroupReceiveAuthorizer(
        store,
        config.aci?.uuid,
        config.groups?.resolveAciBytesByUserIds
      );
      this.cipher.setGroupReceiveAuthorizer(this.groupReceiveAuthorizer);
      this.cipher.setGroupSecretParamsProvider(async (groupId: string) => {
        const masterKey = await store.getMasterKey(groupId);
        if (!masterKey) return null;
        return deriveGroupSecretParams(masterKey);
      });
    }

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
      sealReceipt: (recipientUserId, recipientDeviceId, ciphertextBase64) =>
        this.cipher.sealReceipt(recipientUserId, recipientDeviceId, ciphertextBase64),
    };
  }

  /**
   * Apply one Relay delivery receipt, then announce its deliveries. A
   * receipt that stop() kept from its write throws, so the Relay replays it.
   */
  private async receiveRelayReceipt(receipt: RelayDeliveryReceipt): Promise<void> {
    let applied = false;
    await this.state.relayWork.run(async (work) => {
      work.proceed();
      const events = await this.deliveries.applyRelayReceipt(receipt);
      applied = true;
      await this.announceDeliveries(work.wrapHooks(this.hooks), events);
    });
    if (!applied) throw new RelayWorkStopped();
  }

  /** Run the onDelivered hook once for each event, in order. */
  private async announceDeliveries(
    hooks: SignalProtocolClientHooks,
    events: readonly DeliveredEvent[]
  ): Promise<void> {
    for (const event of events) await callHook(hooks, 'onDelivered', event);
  }

  /**
   * Announce the deliveries that waited for a send of this client message ID
   * to resolve.
   */
  private releaseDeliveries(clientMessageId: string): void {
    void this.state.relayWork
      .run(async (work) => {
        work.proceed();
        const events = await this.deliveries.release(clientMessageId);
        await this.announceDeliveries(work.wrapHooks(this.hooks), events);
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
   */
  private sendDeliveryReceiptAsRelayWork(userId: string, timestamps: number[]): Promise<void> {
    return this.state.relayWork.run(async (work) => {
      const send = this.sendDeliveryReceipt(userId, timestamps, {
        ...this.relayWorkContext(work),
        stopSignal: this.state.relayWork.stopSignal,
      });
      this.deliveryReceiptSends.set(work, send);
      try {
        await send;
      } finally {
        this.deliveryReceiptSends.delete(work);
      }
    });
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

  /** Client context whose hooks call the app through the given relay work. */
  private relayWorkContext(work: RelayWork): SignalProtocolClientContext {
    return { ...this.ctx, hooks: work.wrapHooks(this.hooks) };
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
   * // Linked device; storage must already contain provisioned identity material.
   * const signal = await DefaultSignalProtocolClient.create('user-123', {
   *   deviceId: 2,
   *   storage: provisionedLinkedDeviceStorage
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

      if (deviceId > 1) {
        for (const identityType of activeIdentityTypes) {
          const hasIdentityKey = await finalConfig.storage.hasIdentityKey(identityType);
          if (!hasIdentityKey) {
            throw new Error(
              `Linked device ${deviceId} requires a provisioned ${identityType.toUpperCase()} identity key in storage. ` +
                'Provision the device first, then create the client with that storage.'
            );
          }
        }
      }

      const client = new DefaultSignalProtocolClient(userId, deviceId, finalConfig);
      await client.initialize();
      await client.hydratePersistedState();

      // Cleanup expired sessions and message records on startup.
      // The reference implementation relies on event-driven cleanup (identity change, retry, end-session).
      // We also enforce our maxRecv TTL here to prevent unbounded session growth.
      try {
        await client.sesameManager.cleanupExpiredSessions();
        await client._storage.deleteExpiredMessageRecords(MESSAGE_RECORD_TTL_MS);
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
  private async initialize(): Promise<void> {
    try {
      await this.manager.initialize(getActiveIdentityTypes(this.config));

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
   * Normal sync and linked-device provisioning never call this operation.
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
   * Unified entry point for both foreground (relay) and background (HTTP) message processing.
   * Handles decryption and automatically sends SESAME retry requests on retryable failures.
   *
   * This method:
   * 1. Decodes base64 ciphertext from the envelope
   * 2. Decrypts message using Double Ratchet
   * 3. On retryable error: sends retry request via relay or options callback
   * 4. Re-throws error for caller to handle
   *
   * A `retry_request` envelope holds no plaintext. This method rejects it
   * before decryption and sends no retry request. Give it to
   * `receiveIncomingEnvelopes`, which handles it.
   *
   * A failed envelope that this client asked a resend for, and each resend
   * or null message for it, gives plaintext at most once on both receive
   * paths. When this client processed the envelope, or the application
   * already has that content, this method acknowledges the envelope and
   * throws MESSAGE_DUPLICATE with no decrypt.
   *
   * A null message carries no content. The client consumes a null message
   * when the content adapter reports `nullMessage: true`, and a custom
   * adapter must report it for its own null encoding. This method never
   * returns a null message. It marks the null message processed,
   * acknowledges it and throws MESSAGE_DUPLICATE. A null message for a
   * failed envelope marks that envelope processed, so a redelivery of it
   * is dropped, but a content resend for it that comes later still gives
   * its plaintext.
   *
   * A resend or null message that fails to decrypt, or whose seal fails to
   * open, asks again for its failed envelope under the same retry ID. When
   * the processed record of the failed envelope fails to store after a
   * decrypt, the client writes a warning with the behavior
   * RETRY_FULFILL_WRITE_FAILED, as on every receive path, and this method
   * returns the plaintext. A redelivery of the failed envelope or of
   * another family member can then give the content again. When a
   * processed record of a null message or of its failed envelope fails to
   * store, the client writes a warning with the behavior
   * RETRY_NULL_WRITE_FAILED, as on every receive path, and this method
   * still throws MESSAGE_DUPLICATE. A redelivery of the failed envelope
   * can then give the content.
   *
   * @param envelope - The encrypted message envelope
   * @param options - Transport callbacks for background (no relay) scenarios
   * @returns Decrypted plaintext
   * @throws EncryptionError after sending retry request if decryption fails
   * @throws EncryptionError INVALID_CIPHERTEXT for a `retry_request` envelope
   * @throws EncryptionError MESSAGE_DUPLICATE when this client processed the
   *   envelope, the application already has the content of the failed
   *   envelope of a retry request, or the envelope is a null message
   */
  async processIncomingEnvelope(
    envelope: IncomingEnvelope,
    options?: ProcessEnvelopeOptions
  ): Promise<string> {
    if (envelope.messageType === 'retry_request') {
      throw new EncryptionError(
        'A retry_request envelope holds no plaintext; give it to receiveIncomingEnvelopes',
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType, senderId: envelope.senderUserId }
      );
    }
    // The fingerprint covers the envelope as the Relay delivered it, before
    // any unseal, so every receive path stores one value for it.
    const fingerprint = envelope.id
      ? await deliveredEnvelopeFingerprint(this.userId, this.deviceId, envelope)
      : undefined;
    return receiveInRetryFamily(this._storage, this.logger, envelope, async (family) => {
      if (!(await family.admit())) {
        await this.markMessageDeliveredSilently(envelope.id, options);
        throw new EncryptionError(
          'The application already has the content of this failed envelope',
          EncryptionErrorCode.MESSAGE_DUPLICATE,
          { senderId: envelope.senderUserId }
        );
      }
      const plaintext = await this.decryptIncomingEnvelope(envelope, family, fingerprint, options);
      // A null message carries no content, so the caller never gets it.
      if (this.contentAdapter.inspectContent(plaintext).nullMessage) {
        await family.consumeNull(fingerprint);
        await this.markMessageDeliveredSilently(envelope.id, options);
        throw new EncryptionError(
          'A null message carries no content',
          EncryptionErrorCode.MESSAGE_DUPLICATE,
          { senderId: envelope.senderUserId }
        );
      }
      await family.fulfill();
      return plaintext;
    });
  }

  /**
   * Decrypt one envelope that is not a `retry_request`, under its retry family
   * lock. The fingerprint is that of the delivered envelope, also for the
   * inner envelope of a seal.
   */
  private async decryptIncomingEnvelope(
    envelope: IncomingEnvelope,
    family: RetryFamilyReceive,
    fingerprint: string | undefined,
    options?: ProcessEnvelopeOptions
  ): Promise<string> {
    // Handle sealed sender envelopes: unseal to reveal sender before decrypting
    if (envelope.messageType === 'unidentified_sender' && this.config.sealedSender) {
      const identityKeyPair = await this._storage.getIdentityKey();
      if (!identityKeyPair) {
        throw new EncryptionError(
          'No identity key pair for sealed sender decryption',
          EncryptionErrorCode.DECRYPTION_FAILED
        );
      }

      const recipientPrivateKeyBytes = base64ToBytes(identityKeyPair.dhKey.privateKey);
      let unsealed: Awaited<ReturnType<typeof unsealMessage>>;
      try {
        unsealed = await unsealMessage(
          envelope.ciphertext,
          recipientPrivateKeyBytes,
          this.userId,
          this.deviceId,
          this.config.sealedSender,
          envelope.serverTimestamp,
          this.logger
        );
      } catch (error) {
        // A member whose seal fails to open asks the device of its request
        // for the next attempt, as a member whose decrypt fails does.
        if (family.member !== undefined) {
          await this.sendRetryRequestInternal(
            family.withRequestedSender(envelope),
            error as Error,
            family,
            fingerprint,
            options
          );
        }
        throw error;
      }

      // Process the inner envelope with revealed sender identity. The inner
      // type and the content hint travel inside the seal. Nothing outside it
      // distinguishes a group message from a pairwise one. The same mapping
      // serves the other receive path via `reconstructEnvelope`.
      return this.decryptIncomingEnvelope(
        {
          ...envelope,
          senderUserId: unsealed.senderUserId,
          senderDeviceId: unsealed.senderDeviceId,
          ciphertext: unsealed.innerCiphertextBase64,
          messageType: envelopeTypeForContent(unsealed.contentType),
          contentHint: unsealed.contentHint,
        },
        family,
        fingerprint,
        options
      );
    }

    // Route group messages to sender key decryption. `sender_key` says the
    // payload is a framed SenderKeyMessage. It does not say which group, so
    // the group comes from the frame's distribution identifier resolved
    // against the local sender key store.
    if (envelope.messageType === 'sender_key') {
      // Framed SenderKeyMessage: base64 → bytes (Uint8Array)
      const framedBytes = base64ToBytes(envelope.ciphertext as Base64);
      const groupId = await this.senderKeyManager.resolveGroupForFramedMessage(
        framedBytes,
        envelope.senderUserId,
        envelope.senderDeviceId
      );
      if (groupId === null) {
        throw new EncryptionError(
          `No sender key from ${envelope.senderUserId} matches this group message - request key distribution`,
          EncryptionErrorCode.SESSION_NOT_FOUND
        );
      }
      return this.decryptGroupMessage(
        groupId,
        envelope.senderUserId,
        envelope.senderDeviceId,
        framedBytes
      );
    }

    const senderAddress = ProtocolAddress.create(envelope.senderUserId, envelope.senderDeviceId);

    try {
      // Decode ciphertext: base64 → UTF-8 bytes → JSON string
      // Relay stores as base64(UTF-8(JSON)), we need to reverse both encodings
      const ciphertextBytes = base64ToBytes(envelope.ciphertext as Base64);
      const ciphertext = utf8Decode(ciphertextBytes) as Ciphertext;

      // Decrypt message using Double Ratchet
      const plaintext = await this.decryptMessage(senderAddress, ciphertext);

      return plaintext;
    } catch (error) {
      // Send retry request if error is retryable (per SESAME spec §4.1)
      if (isRetryableDecryptionError(error as Error)) {
        await this.sendRetryRequestInternal(
          envelope,
          error as Error,
          family,
          fingerprint,
          options
        );
      }

      // Re-throw so caller can handle (log, skip message, etc.)
      throw error;
    }
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
   * @param options - Transport callbacks for background scenarios
   * @returns Array of results, each either success (plaintext) or failure (error)
   *
   * @example
   * ```typescript
   * const results = await signal.processIncomingEnvelopes(pendingMessages);
   * for (const result of results) {
   *   if ('plaintext' in result) {
   *     handleDecryptedMessage(result.envelope, result.plaintext);
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
      | { envelope: IncomingEnvelope; plaintext: string }
      | { envelope: IncomingEnvelope; error: Error }
    >
  > {
    // Sort PreKeyMessages first - they establish sessions needed by subsequent ciphertexts
    // This is internal - callers do not need to know about SESAME session convergence
    const sorted = sortEnvelopesForDecryption(envelopes);

    const results: Array<
      | { envelope: IncomingEnvelope; plaintext: string }
      | { envelope: IncomingEnvelope; error: Error }
    > = [];

    for (const envelope of sorted) {
      try {
        const plaintext = await this.processIncomingEnvelope(envelope, options);
        results.push({ envelope, plaintext });
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
   */
  async receiveIncomingEnvelopes(envelopes: IncomingEnvelope[]): Promise<{
    processedMessageIds: string[];
    failedMessageIds: string[];
  }> {
    if (!this.hooks?.onMessageDecrypted) {
      throw new Error('Register onMessageDecrypted before receiving Relay messages');
    }
    const processedMessageIds: string[] = [];
    const failedMessageIds: string[] = [];
    const context = { ...this.ctx, cipher: this.cipher };
    for (const envelope of sortEnvelopesForDecryption(envelopes)) {
      try {
        const processed = await RelaySubscriptionOps.processRelayMessage(
          context,
          {
            ...envelope,
            targetUserId: this.userId,
            targetDeviceId: this.deviceId,
            deliveryClass: 'user-visible',
            messageType: (envelope.messageType ?? 'ciphertext') as Envelope['messageType'],
          },
          this.relaySubscriptionState,
          this.relaySubscriptionCallbacks(context),
          { ...this.relaySubscriptionConfig, acknowledgeFailures: false }
        );
        (processed ? processedMessageIds : failedMessageIds).push(envelope.id);
      } catch {
        failedMessageIds.push(envelope.id);
      }
    }
    return { processedMessageIds, failedMessageIds };
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
    // Normalize all inputs to Uint8Array before calling cipher.encrypt()
    let plaintextBytes: Uint8Array;
    let clientTimestamp: number | undefined;
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

    // A receipt for this send waits until the send resolves.
    const clientMessageId = options?.clientMessageId ?? (await generateUuidV4());
    const encrypt = (sendContext: SignalProtocolClientContext) =>
      this.cipher.encrypt(
        recipientId,
        plaintextBytes,
        {
          ...options,
          clientMessageId,
          ...(clientTimestamp !== undefined && { timestamp: clientTimestamp }),
        },
        this.sendSessionCallbacks(() => sendContext, stopSignal),
        stopSignal
      );
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
    this.releaseDeliveries(clientMessageId);
    if (profileKey) await profileKeys?.delivered(recipientId, profileKey);
    return clientTimestamp !== undefined ? { ...result, clientTimestamp } : result;
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

    this.relayUnsubscribe = this.relay.subscribe(
      this.userId,
      this.deviceId,
      (envelope) => {
        const handled = this.state.relayWork.run((work) => {
          const ctx = this.relayWorkContext(work);
          return RelaySubscriptionOps.handleRelayMessage(
            { ...ctx, cipher: this.cipher, stopSignal: work.stopSignal },
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
   */
  private async sendDeliveryReceipt(
    recipientUserId: string,
    timestamps: number[],
    ctx: SignalProtocolClientContext = this.receiptContext()
  ): Promise<void> {
    return this.sendReceipt(recipientUserId, timestamps, ReceiptType.DELIVERY, ctx);
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
      // receipt deadline. A delivery or retry request whose app hook returns
      // during the wait writes nothing more, and the relay delivers it again
      // after the next start. A receipt send is not stopped here, because the
      // relay has the acknowledgment of its messages and does not deliver
      // them again
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

    // 8. Cleanup expired message records (SESAME spec §6.2)
    try {
      const deleted = await this._storage.deleteExpiredMessageRecords(MESSAGE_RECORD_TTL_MS);
      if (deleted > 0) {
        this.logger.debug('Cleaned up expired message records', {
          category: 'E2EE',
          data: { deleted },
        });
      }
    } catch (error) {
      // Log but do not fail stop
      this.logger.warn('Error cleaning up message records', {
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
    return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      await this.groupReceiveAuthorizer?.(rawGroupId, senderId, 'distribution');
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
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param framedMessage - Framed SenderKeyMessage bytes
   * @returns Decrypted plaintext
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
    return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      await this.groupReceiveAuthorizer?.(rawGroupId, senderId, 'message');
      return GroupOps.decryptGroupMessage(
        this.ctx, this.senderKeyManager, rawGroupId, senderId, senderDeviceId, framedMessage
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
   * Sync group state from server.
   */
  async syncGroup(groupId: GroupId): Promise<DecryptedGroup> {
    return GroupOps.syncGroup(this.ctx, await this.groups, groupId);
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
