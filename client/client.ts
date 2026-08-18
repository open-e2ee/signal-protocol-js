/**
 * SignalProtocolClient - initialized client class for encrypted messaging.
 *
 * @layer 1 - API
 * @boundary ISignalProtocolClient
 *
 * Application code should usually create clients with `createSignalProtocolClient()`.
 * Use `SignalProtocolClient.create()` directly when lower-level integration code already
 * owns the flattened config shape.
 *
 * @example Basic usage
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 * import { inMemoryStore } from '@open-e2ee/signal-protocol-sdk/local/store/memory';
 * import { inMemoryRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/memory';
 *
 * const relay = inMemoryRelay();
 * const signal = await createSignalProtocolClient({
 *   identity: { userId: 'alice' },
 *   adapters: { storage: inMemoryStore(), relay },
 * });
 *
 * await signal.syncToServer();
 * await signal.send('bob', 'Hello!');
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
 * import { SignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await SignalProtocolClient.create(userId, {
 *   storage,
 *   relay,
 * });
 * ```
 */

import AsyncLock from 'async-lock';
import type { ISignalProtocolRelayServer, Envelope, Unsubscribe } from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import { SignalProtocolManager } from '../internal/manager';
import { SesameManager } from '../internal/sesame';
import type { Ciphertext, IdentityType, PreKeyBundle, PublicKey } from '../keys';
import { createCompositeIdentityV1 } from '../keys/identity';
import type {
  ISignalProtocolClient,
  ISignalProtocolLocalStore,
  ISignalProtocolManager,
  Base64,
} from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { base64ToBytes } from '../internal/crypto';
import type { SignalProtocolClientHooks } from './event-hooks';
import { ProtocolAddress } from '../types/address';
import {
  getActiveIdentityTypes,
  resolveSignalProtocolStrategy,
  type ProgressCallback,
  type SignalProtocolClientConfig,
} from './config';
import type { ISesameManager, SesameMessage, SesameStats } from '../internal/sesame/types';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';
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
import { SignalProtocolServiceCipher, sortEnvelopesForDecryption } from './signal-service-cipher';
import { establishMultiDeviceSessions } from '../internal/sesame/device-registry';
import { isRetryableDecryptionError } from './retry-utils';
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
import * as RelaySubscriptionOps from './relay-subscription';
import { SignalProtocolClientState, SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
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
  IGroupStateStore,
} from '../internal/groups';
import type { GroupId } from '../internal/groups/group-id';
import { SignalProtocolGroupStateStore } from '../internal/groups/sdk-store';

// Re-export for backwards compatibility (definition moved to constants.ts to avoid require cycles)
export {};
export { IMPLICIT_ENVELOPE_TYPES } from './constants';

/**
 * Module-level lock for storage initialization.
 * Prevents multiple concurrent SignalProtocolClient.create() calls from creating
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
 * This client implements the ISignalProtocolClient interface and wraps
 * SignalProtocolManager with additional high-level functionality.
 *
 * @category Primary API
 */
export class SignalProtocolClient implements ISignalProtocolClient {
  private readonly manager: ISignalProtocolManager;
  private readonly _storage: ISignalProtocolLocalStore;
  private readonly relay?: ISignalProtocolRelayServer;
  private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore;
  private readonly config: SignalProtocolClientConfig;
  private readonly _userId: string;
  public readonly logger: Required<ILogger>;
  private hooks: SignalProtocolClientHooks;
  private readonly contentAdapter: SignalProtocolContentAdapter;

  // Multi-device support (Phase 2)
  public readonly deviceId: number; // 1 = primary, 2-5 = linked devices

  /**
   * Get user ID for this client instance
   * @see ISignalProtocolClient.userId
   */
  public get userId(): string {
    return this._userId;
  }
  private readonly sesameManager: ISesameManager; // Sesame protocol manager for multi-device support
  private readonly _address: ProtocolAddress; // Cached own address

  // Group messaging support (Sender Keys)
  private readonly senderKeyManager: SenderKeyManager;

  // Group state management
  private groupManager?: GroupManager;
  private groupStore?: IGroupStateStore;

  // Cipher coordination (encrypts/decrypts, routes to appropriate cipher)
  private readonly cipher: SignalProtocolServiceCipher;

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

  private relayUnsubscribe?: Unsubscribe;
  private retryUnsubscribe?: Unsubscribe;

  /**
   * Cached sender certificate for sealed sender.
   * Lazily fetched and refreshed when expired (24h validity, 5min margin).
   */
  private cachedSenderCertificate: string | null = null;
  private cachedCertificateExpiry: number = 0;

  /**
   * Centralized state management for retry/rotation tracking
   * @see SignalProtocolClientState for state details
   */
  private readonly state = new SignalProtocolClientState();

  /**
   * Get retry rate limiting state for retry operations
   */
  private get rateLimitState(): RetryOps.RetryRateLimitState {
    return this.state.getRateLimitState();
  }

  // Constants are now imported from state.ts for single source of truth
  // See SIGNAL_PROTOCOL_CLIENT_CONSTANTS for timing and retry configuration

  /**
   * Private constructor - use SignalProtocolClient.create() to instantiate
   *
   * @param userId - User identifier
   * @param deviceId - Device identifier (1 = primary, 2-5 = linked devices)
   * @param config - Configuration for the client
   */
  private constructor(userId: string, deviceId: number, config: SignalProtocolClientConfig) {
    this._userId = userId;
    this.deviceId = deviceId;
    this.config = config;
    this.logger = resolveSignalProtocolLogger(config.logger);
    this.hooks = config.hooks || {};
    this.contentAdapter = config.contentAdapter ?? createDefaultSignalProtocolContentAdapter();

    // Dependency injection: use the provided relay adapter when configured.
    this.relay = config.relay;

    // Dependency injection: use the remote object store for encrypted attachments.
    this.remoteObjectStore = config.remoteObjectStore;

    // Dependency injection: Storage is always provided by create() callers.
    if (!config.storage) {
      throw new Error('Storage must be provided by SignalProtocolClient.create() callers');
    }
    this._storage = config.storage;
    (
      this._storage as ISignalProtocolLocalStore & {
        setLogger?: (logger?: ILogger) => void;
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
      new SignalProtocolManager(this._storage, config.protocolStrategy, this.logger);

    // Validate manager was created successfully before initializing Sesame
    if (!this.manager) {
      throw new EncryptionError(
        'Protocol manager must be initialized before Sesame manager',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    // Initialize Sesame manager for multi-device support
    this.sesameManager = new SesameManager(
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

    // Initialize the group manager if configured
    if (config?.groups) {
      const capability = this.relay?.groupServer;
      const server = config.groups.server ?? capability?.server;
      const issueCredential =
        config.groups.issueCredential ??
        (capability
          ? () => capability.issueAuthCredential(this._userId)
          : undefined);
      const issueProfileKeyCredential =
        config.groups.issueProfileKeyCredential ??
        (capability
          ? () =>
              capability.issueProfileKeyCredential(
                this._userId,
                config.groups!.profileKey
              )
          : undefined);

      if (!server || !issueCredential || !issueProfileKeyCredential) {
        const missing = [
          !server ? 'server' : undefined,
          !issueCredential ? 'issueCredential' : undefined,
          !issueProfileKeyCredential
            ? 'issueProfileKeyCredential'
            : undefined,
        ].filter((value): value is string => value !== undefined);
        throw new Error(
          `Groups require the relay.groupServer capability or explicit overrides; missing: ${missing.join(', ')}`
        );
      }
      if (!config.aci) {
        throw new Error(
          'Groups require the client identity ACI; set identity.aci'
        );
      }

      const trustRoot = decodeGroupTrustRoot(config.groups.trustRoot);
      this.groupStore =
        config.groups.store ??
        new SignalProtocolGroupStateStore(this._storage);
      const endorsementManager = config.groups.endorsementManager;
      endorsementManager?.assertEndorsementRootPublicKey(
        trustRoot.endorsementRootPublicKey
      );

      this.groupManager = new GroupManager({
        store: this.groupStore,
        server,
        issueCredential,
        credentialPublicKey: trustRoot.credentialPublicKey,
        serverSigningPublicKey: trustRoot.serverSigningPublicKey,
        allowUnauthenticatedGroupHistory:
          config.groups.allowUnauthenticatedGroupHistory,
        onConfigurationWarning: config.groups.onConfigurationWarning,
        aci: config.aci,
        pni: config.pni,
        issueProfileKeyCredential,
        profileKeyCredentialPublicKey:
          trustRoot.profileKeyCredentialPublicKey,
        profileKey: config.groups.profileKey,
        onSenderKeyRotation: async (groupId) => {
          // Forward to existing sender key rotation
          await this.rotateGroupSenderKey(groupId as string);
        },
        onEndorsementsInvalidated: endorsementManager
          ? async (groupId) => {
              await endorsementManager.clearGroupEndorsements(groupId);
            }
          : undefined,
      });
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
      this.logger
    );
    if (this.groupManager) {
      this.cipher.setGroupSendBarrierChecker((groupId) =>
        this.groupManager!.assertGroupSendAllowed(groupId)
      );
    }

    // Set up auto-session establishment callback
    // This enables lazy session creation when sending to users without established sessions
    if (this.relay) {
      this.cipher.setSessionEstablisher(async (recipientUserId: string) => {
        return establishMultiDeviceSessions(this, this.relay!, recipientUserId);
      });

      // Set up stale session refresh callback
      // Stale-device recovery archives the old session, fetches a fresh bundle,
      // and establishes a replacement.
      // Per SESAME §3.2: session is archived (not deleted) to handle delayed messages
      this.cipher.setStaleSessionRefresher(
        async (recipientUserId: string, recipientDeviceId: number): Promise<boolean> => {
          try {
            const address = ProtocolAddress.create(recipientUserId, recipientDeviceId);

            // 1. Archive the stale session (preserves for delayed message decryption)
            await this.archiveSession(address);

            this.logger.debug('Archived stale session for refresh', {
              category: 'E2EE',
              data: { recipientUserId, recipientDeviceId },
            });

            // 2. Fetch fresh prekey bundle
            const freshBundle = await this.relay!.fetchPreKeyBundle(
              recipientUserId,
              recipientDeviceId
            );

            if (!freshBundle) {
              this.logger.warn('No prekey bundle available for stale session refresh', {
                category: 'E2EE',
                data: { recipientUserId, recipientDeviceId },
              });
              return false;
            }

            // 3. Establish new session with fresh keys
            await this.establishSession(address, freshBundle);

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
        }
      );
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
        const { base64ToBytes: b64ToBytes } = await import('../internal/crypto');
        return {
          senderCertificateBase64: certBase64,
          senderIdentityPrivate: b64ToBytes(identityKeyPair.dhKey.privateKey),
          senderIdentityPublic: b64ToBytes(identityKeyPair.dhKey.publicKey),
          config: this.config.sealedSender!,
        };
      });
    }

    if (config?.sealedSender?.contactStateStore) {
      this.cipher.setContactProfileStateStore(config.sealedSender.contactStateStore);
    }

    // Set up endorsement manager if configured
    if (config?.groups?.endorsementManager) {
      this.cipher.setEndorsementManager(config.groups.endorsementManager);
    }

    // Set up group secret params provider. Derives params from master key in store
    if (this.groupStore) {
      const store = this.groupStore;
      this.cipher.setGroupSecretParamsProvider(async (groupId: string) => {
        const masterKey = await store.getMasterKey(groupId);
        if (!masterKey) return null;
        const { deriveGroupSecretParams } = await import('../internal/protocol/zk/groups');
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
      const endorsementManager = groupConfig.endorsementManager!;
      const groupStore = this.groupStore;
      const groupManager = this.groupManager;
      const relay = this.relay;
      const selfUserId = this._userId;

      this.cipher.setEndorsementRefresher(async (groupId: string, memberUserIds: string[]) => {
        // 1. Build ZK authorization (credential presentation + group public params)
        const authorization = await groupManager.getAuthorization(groupId);

        // 2. Get group secret params for endorsement processing
        const masterKey = await groupStore.getMasterKey(groupId);
        if (!masterKey) return false;
        const { deriveGroupSecretParams } = await import('../internal/protocol/zk/groups');
        const secretParams = deriveGroupSecretParams(masterKey);

        // 3. Convert groupId to bytes for relay call
        const groupIdBytes = new TextEncoder().encode(groupId);

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
        const { SERVICE_ID_ACI } = await import('../internal/protocol/zk/groups/uid-struct');

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
      this.logger.debug('SignalProtocolClient created', {
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
    };
  }

  /**
   * Whether the client enables and configures sealed sender.
   */
  get isSealedSenderEnabled(): boolean {
    const ss = this.config.sealedSender;
    return !!(ss && ss.accessMode !== 'disabled' && ss.trustRoots.length > 0);
  }

  /**
   * Fetch (or return cached) sender certificate for sealed sender.
   *
   * Uses the configured certificateProvider or relay.fetchSenderCertificate().
   * Caches the result until expiry (24h certificate, 5min safety margin).
   *
   * @returns Base64-encoded serialized SenderCertificate
   * @throws if no certificate provider is available
   */
  async fetchSenderCertificate(): Promise<string> {
    const { SEALED_SENDER_CERTIFICATE_MARGIN_MS } = await import('./config');

    // Return cached if still valid (with 5min safety margin)
    if (this.cachedSenderCertificate && Date.now() < this.cachedCertificateExpiry) {
      return this.cachedSenderCertificate;
    }

    // Fetch from configured provider or relay
    let certBase64: string;
    if (this.config.sealedSender?.certificateProvider) {
      certBase64 = await this.config.sealedSender.certificateProvider();
    } else if (this.relay?.fetchSenderCertificate) {
      certBase64 = await this.relay.fetchSenderCertificate(this.deviceId);
    } else {
      throw new EncryptionError(
        'No sender certificate provider configured. Set sealedSender.certificateProvider or use a relay that supports fetchSenderCertificate.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    // Cache with margin
    const CERTIFICATE_VALIDITY_MS = 24 * 60 * 60 * 1000;
    this.cachedSenderCertificate = certBase64;
    this.cachedCertificateExpiry =
      Date.now() + CERTIFICATE_VALIDITY_MS - SEALED_SENDER_CERTIFICATE_MARGIN_MS;

    return certBase64;
  }

  /**
   * Get GroupManager, throwing if not configured.
   */
  private get groups(): GroupManager {
    if (!this.groupManager) {
      throw new EncryptionError(
        'Groups not configured. Provide groups config to SignalProtocolClient.create().',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    return this.groupManager;
  }

  /**
   * Get retry configuration for retry operations
   */
  private get retryConfig(): RetryOps.RetryConfig {
    return {
      keyRotationDebounceMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.KEY_ROTATION_DEBOUNCE_MS,
      retryDedupWindowMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.RETRY_DEDUP_WINDOW_MS,
      retryCleanupIntervalMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.RETRY_CLEANUP_INTERVAL_MS,
    };
  }

  /**
   * Get retry dedup state for retry operations
   */
  private get retryDedupState(): RetryOps.RetryDedupState {
    return this.state.getRetryDedupState();
  }

  /**
   * Get retry callbacks for retry operations
   */
  private get retryCallbacks(): RetryOps.RetryCallbacks {
    return {
      archiveSession: (address) => this.archiveSession(address),
      establishSession: (address, bundle) => this.establishSession(address, bundle),
      send: (recipientId, content, options) => this.send(recipientId, content, options),
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
   * Get relay subscription callbacks (delegate back to SignalProtocolClient methods)
   */
  private get relaySubscriptionCallbacks(): RelaySubscriptionOps.RelaySubscriptionCallbacks {
    return {
      forcePreKeyRotation: () => this.regeneratePreKeysWithFreshIds(),
      handleDeliveryReceipt: (envelope, receipt) => this.handleDeliveryReceipt(envelope, receipt),
      handleTypingIndicator: (envelope, typing) => this.handleTypingIndicator(envelope, typing),
      sendDeliveryReceipt: (userId, timestamps) => this.sendDeliveryReceipt(userId, timestamps),
    };
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
   * Create and initialize a new SignalProtocolClient instance.
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
   * @returns Fully initialized SignalProtocolClient instance
   *
   * @example
   * ```typescript
   * import { SignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
   * import { convexRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
   *
   * // Local-only primary device.
   * const signal = await SignalProtocolClient.create('user-123', {
   *   storage,
   * });
   *
   * // Linked device; storage must already contain provisioned identity material.
   * const signal = await SignalProtocolClient.create('user-123', {
   *   deviceId: 2,
   *   storage: provisionedLinkedDeviceStorage
   * });
   *
   * // With relay sync.
   * const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });
   * const signal = await SignalProtocolClient.create('user-123', {
   *   storage,
   *   relay,
   *   onProgress: ({ stage, percent, message }) => {
   *     console.log(`${stage}: ${percent}% - ${message}`);
   *   }
   * });
   *
   * // With full configuration
   * const signal = await SignalProtocolClient.create('user-123', {
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
   * const signal = await SignalProtocolClient.create('local-user', {
   *   protocolManager: inMemoryManager,
   *   storage: inMemoryStorage
   * });
   * ```
   */
  static async create(
    userId: string,
    config: SignalProtocolClientConfig
  ): Promise<SignalProtocolClient> {
    const deviceId = config?.deviceId ?? 1; // Default to primary device

    // Use locking to prevent race conditions when multiple create() calls happen concurrently.
    // The lock allows only one storage instance per userId, which prevents database lock
    // contention and session state corruption.
    return storageLock.acquire(`storage-init-${userId}`, async () => {
      // Storage is required - SignalProtocolClient is platform-agnostic
      // Each platform must provide its own storage implementation
      if (!config?.storage) {
        throw new Error(
          'SignalProtocolClient.create() requires storage. ' +
            'Expo: import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo"; ' +
            'Web: import { indexedDbStore } from "@open-e2ee/signal-protocol-sdk/local/store/web"; ' +
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

      const client = new SignalProtocolClient(userId, deviceId, finalConfig);
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

      // Start retry request subscription if relay supports it (SESAME spec §6.2)
      if (!syncFailed && finalConfig?.relay?.subscribeRetryRequests) {
        client.startRetryRequestSubscription();
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
   * const alice = await SignalProtocolClient.create('alice', { storage: aliceStorage });
   * const bob = await SignalProtocolClient.create('bob', { storage: bobStorage });
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
   * @param envelope - The encrypted message envelope
   * @param options - Transport callbacks for background (no relay) scenarios
   * @returns Decrypted plaintext
   * @throws EncryptionError after sending retry request if decryption fails
   */
  async processIncomingEnvelope(
    envelope: IncomingEnvelope,
    options?: ProcessEnvelopeOptions
  ): Promise<string> {
    // Handle sealed sender envelopes: unseal to reveal sender before decrypting
    if (envelope.messageType === 'unidentified_sender' && this.config.sealedSender) {
      const { unsealMessage, envelopeTypeForContent } = await import('./sealed-sender-ops');
      const identityKeyPair = await this._storage.getIdentityKey();
      if (!identityKeyPair) {
        throw new EncryptionError(
          'No identity key pair for sealed sender decryption',
          EncryptionErrorCode.DECRYPTION_FAILED
        );
      }

      const recipientPrivateKeyBytes = base64ToBytes(identityKeyPair.dhKey.privateKey);
      const unsealed = await unsealMessage(
        envelope.ciphertext,
        recipientPrivateKeyBytes,
        this.userId,
        this.deviceId,
        this.config.sealedSender,
        this.logger
      );

      // Process the inner envelope with revealed sender identity. The inner
      // type travels inside the seal. Nothing outside it distinguishes a
      // group message from a pairwise one. The same mapping serves the other
      // receive path via `reconstructEnvelope`.
      return this.processIncomingEnvelope(
        {
          ...envelope,
          senderUserId: unsealed.senderUserId,
          senderDeviceId: unsealed.senderDeviceId,
          ciphertext: unsealed.innerCiphertextBase64,
          messageType: envelopeTypeForContent(unsealed.contentType),
        },
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
      const ciphertext = new TextDecoder().decode(ciphertextBytes) as Ciphertext;

      // Decrypt message using Double Ratchet
      const plaintext = await this.decryptMessage(senderAddress, ciphertext);

      return plaintext;
    } catch (error) {
      // Send retry request if error is retryable (per SESAME spec §4.1)
      if (isRetryableDecryptionError(error as Error)) {
        await this.sendRetryRequestInternal(envelope, error as Error, options);
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
   * Internal: Send SESAME retry request for failed decryption.
   *
   * Uses relay if available, otherwise falls back to options callback.
   * Called automatically by processIncomingEnvelope on retryable errors.
   *
   * @param envelope - The failed message envelope
   * @param error - The decryption error
   * @param options - Optional transport callbacks (for background without relay)
   */
  private async sendRetryRequestInternal(
    envelope: IncomingEnvelope,
    error: Error,
    options?: ProcessEnvelopeOptions
  ): Promise<void> {
    return RetryOps.sendRetryRequestInternal(
      this.ctx as RetryOps.RetryContext,
      envelope,
      error,
      this.rateLimitState,
      { forcePreKeyRotation: () => this.regeneratePreKeysWithFreshIds() },
      this.retryConfig,
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
    // Normalize all inputs to Uint8Array before calling cipher.encrypt()
    let plaintextBytes: Uint8Array;
    let clientTimestamp: number | undefined;

    if (isDataMessage(content)) {
      // DataMessage path: build Content, set timestamp, serialize to protobuf (application send-pipeline ordering)
      const timestamp = (content.timestamp as number | undefined) ?? Date.now();
      clientTimestamp = timestamp;
      const dm: DataMessageInput = { ...content, timestamp };
      plaintextBytes = this.contentAdapter.serializeDataMessage(dm);
    } else if (typeof content === 'string') {
      plaintextBytes = new TextEncoder().encode(content);
    } else {
      plaintextBytes = content; // already Uint8Array
    }

    const result = await this.cipher.encrypt(recipientId, plaintextBytes, {
      ...options,
      ...(clientTimestamp !== undefined && { timestamp: clientTimestamp }),
    });
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
        'Remote object storage not configured. Provide remoteObjectStore in SignalProtocolClient.create() config.',
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
        'Remote object storage not configured. Provide remoteObjectStore in SignalProtocolClient.create() config.',
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
    const accepted = await SessionOps.acceptIdentityRotation(
      this.ctx,
      userId,
      identity,
      identityType
    );

    // A retry that first discovered the changed tuple may already have failed
    // closed and entered the short-lived dedup window. Explicit acceptance is
    // the authority to try those still-pending requests again. It is never
    // inferred from the retry request itself.
    const retryPrefix = `${userId}:`;
    for (const key of this.retryDedupState.recentRetryRequests.keys()) {
      if (key.startsWith(retryPrefix)) {
        this.retryDedupState.recentRetryRequests.delete(key);
      }
    }
    if (this.retryUnsubscribe) {
      this.retryUnsubscribe();
      this.retryUnsubscribe = undefined;
      this.startRetryRequestSubscription();
    }

    return accepted;
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
   * after the SignalProtocolClient exists. ServicesProvider uses this
   * to wire up ContentManager's decryption hook.
   *
   * @param name - The hook name to register
   * @param callback - The callback function to invoke
   *
   * @example
   * ```typescript
   * // In ServicesProvider: wire up ContentManager after creation
   * const signal = await SignalProtocolClient.create(userId, { storage, relay });
   * const content = new ContentManager({ db, signal });
   *
   * signal.registerHook('onMessageDecrypted', content.getDecryptionHook());
   * signal.startRelaySubscription(); // Now safe to start
   * ```
   *
   * @see ISignalProtocolClient.registerHook
   */
  registerHook<K extends keyof import('./event-hooks').SignalProtocolClientHooks>(
    name: K,
    callback: NonNullable<import('./event-hooks').SignalProtocolClientHooks[K]>
  ): void {
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
   * When configured with both `relay` and `onMessageDecrypted` hook, SignalProtocolClient will:
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
   *
   * @see ISignalProtocolClient.startRelaySubscription
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

    // Create extended context with cipher for relay subscription operations
    const relayCtx: RelaySubscriptionOps.RelaySubscriptionContext = {
      ...this.ctx,
      cipher: this.cipher,
    };

    this.relayUnsubscribe = this.relay.subscribe(
      this.userId,
      this.deviceId,
      async (envelope) => {
        await RelaySubscriptionOps.handleRelayMessage(
          relayCtx,
          envelope,
          this.relaySubscriptionState,
          this.relaySubscriptionCallbacks,
          this.relaySubscriptionConfig
        );
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
   * SignalProtocolClient state. startRelaySubscription() restarts the subscription.
   *
   * Use this when the app backgrounds to let the background task handle messages.
   * Resume when the app foregrounds for real-time message delivery.
   *
   * @see ISignalProtocolClient.stopRelaySubscription
   */
  public stopRelaySubscription(): void {
    // Flush any pending batched delivery receipts before unsubscribing
    const { receiptAccumulator } = this.relaySubscriptionState;
    for (const [userId, timestamps] of receiptAccumulator.pending) {
      if (timestamps.length > 0) {
        this.sendDeliveryReceipt(userId, timestamps).catch((_error) => {
          this.logger.warn('Failed to send delivery receipt', {
            category: 'E2EE',
            data: { userId },
          });
        });
      }
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
   * Start listening for retry requests from recipients (SESAME spec §6.2)
   *
   * When a recipient cannot decrypt a message, they send a retry request.
   * This method subscribes to incoming retry requests and processes them
   * by resending the original message with a new session.
   *
   * Automatically started if relay.subscribeRetryRequests is available.
   * Call this manually if you need to restart the subscription.
   */
  public startRetryRequestSubscription(): void {
    if (!this.relay || !this.relay.subscribeRetryRequests) {
      this.logger.debug('Relay does not support retry request subscription', {
        category: 'E2EE',
      });
      return;
    }

    // Avoid duplicate subscriptions
    if (this.retryUnsubscribe) {
      this.logger.debug('Retry request subscription already active', {
        category: 'E2EE',
      });
      return;
    }

    this.logger.debug('Starting retry request subscription', {
      category: 'E2EE',
      data: { userId: this.userId, deviceId: this.deviceId },
    });

    this.retryUnsubscribe = this.relay.subscribeRetryRequests(
      this.userId,
      this.deviceId,
      async (retryRequest) => {
        await this.handleRetryRequestAndResend(retryRequest);
      }
    );
  }

  /**
   * Handle a retry request and resend the original message
   *
   * Per SESAME spec §4.1 (Resending Process):
   * 1. Look up MessageRecord by sequence number
   * 2. Validate retry limits and message TTL
   * 3. Check session state:
   *    - If NO active session OR active session IS orphaned (matches MessageRecord.sessionStateId):
   *      → Fetch prekey bundle and create new session
   *    - If DIFFERENT active session exists:
   *      → Use it directly (no prekey fetch, prevents rate limit issues)
   * 4. Re-encrypt and send the original message
   *
   * This prevents infinite retry loops where each retry creates a new session
   * with different header keys.
   *
   * @param retryRequest - The retry request from the recipient
   */
  private async handleRetryRequestAndResend(
    retryRequest: import('../internal/sesame/types').RetryRequest
  ): Promise<void> {
    return RetryOps.handleRetryRequestAndResend(
      this.ctx as RetryOps.RetryContext,
      retryRequest,
      this.retryDedupState,
      this.retryCallbacks,
      this.retryConfig
    );
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
   *
   */
  private async sendDeliveryReceipt(recipientUserId: string, timestamps: number[]): Promise<void> {
    return this.sendReceipt(recipientUserId, timestamps, ReceiptType.DELIVERY);
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
   * Internal method to send receipt (delivery or read)
   *
   * Delegates to MessageOps.sendReceipt for implementation.
   */
  private async sendReceipt(
    recipientUserId: string,
    timestamps: number[],
    type: ReceiptType
  ): Promise<void> {
    return MessageOps.sendReceipt(this.ctx, recipientUserId, timestamps, type);
  }

  /**
   * Handle incoming delivery/read receipt and clean up MessageRecords
   *
   * Delegates to MessageOps.handleDeliveryReceipt for implementation.
   */
  private async handleDeliveryReceipt(
    envelope: Envelope,
    receipt: ParsedReceiptContent | null
  ): Promise<void> {
    return MessageOps.handleDeliveryReceipt(this.ctx, envelope, receipt);
  }

  /**
   * Handle incoming typing indicator
   *
   * Delegates to MessageOps.handleTypingIndicator for implementation.
   */
  private async handleTypingIndicator(
    envelope: Envelope,
    typing: ParsedTypingContent | null
  ): Promise<void> {
    return MessageOps.handleTypingIndicator(this.ctx, envelope, typing);
  }

  /**
   * Stop the Signal Protocol client and clean up resources
   *
   * Call this when the user logs out or the app shuts down.
   * Unsubscribes from relay server and cleans up any pending operations.
   *
   * @example
   * ```typescript
   * // On logout
   * await signal.stop();
   * ```
   */
  async stop(): Promise<void> {
    // 1. Stop relay subscription
    if (this.relayUnsubscribe) {
      this.relayUnsubscribe();
      this.relayUnsubscribe = undefined;
      this.logger.debug('Relay subscription stopped', { category: 'E2EE' });
    }

    // 2. Stop retry request subscription
    if (this.retryUnsubscribe) {
      this.retryUnsubscribe();
      this.retryUnsubscribe = undefined;
      this.logger.debug('Retry request subscription stopped', {
        category: 'E2EE',
      });
    }

    // 3. Cleanup expired Sesame sessions
    try {
      await this.sesameManager.cleanupExpiredSessions();
    } catch (error) {
      this.logger.warn('Error cleaning up Sesame sessions', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }

    // 4. Cleanup expired message records (SESAME spec §6.2)
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

    // 5. Clear internal tracking state via state manager
    this.state.clearForStop();

    this.logger.debug('SignalProtocolClient stopped', {
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

  /**
   * Run periodic cleanup of internal tracking state.
   *
   * Safe to call frequently - internally throttled to avoid overhead.
   * Recommended call sites:
   * - App foreground transition
   * - After successful message batch processing
   * - Periodically during long sessions
   *
   * Cleans up:
   * - Expired retry dedup entries (recentRetryRequests)
   *
   * @returns Number of entries cleaned up
   */
  runPeriodicCleanup(): number {
    const result = this.state.runPeriodicCleanup();

    if (result.cleaned > 0) {
      this.logger.debug('Periodic cleanup completed', {
        category: 'E2EE',
        data: { cleaned: result.cleaned },
      });
    }

    return result.cleaned;
  }

  // ============================================================================
  // KEY ROTATION (delegated to key-rotation.ts)
  // ============================================================================

  /**
   * Rotate EC signed prekey
   *
   * Rotates only once the current prekey is older than the configured refresh
   * interval ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default). It
   * is therefore safe to call more often than that. Generates a new EC signed
   * prekey
   * and uploads it to the relay if configured.
   *
   * @returns True if the client rotated the key, false if not needed yet
   */
  async rotateEcSignedPreKey(): Promise<boolean> {
    return KeyRotationOps.rotateEcSignedPreKey(this.ctx);
  }

  /**
   * Rotate the post-quantum KEM last-resort prekey.
   *
   * Shares the signed prekey's refresh interval
   * ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default) and rotates
   * only after that interval elapses. Generates fresh ML-KEM/Kyber-compatible
   * key material and uploads it to the relay if configured.
   *
   * @returns True if the client rotated the key, false if not needed yet
   */
  async rotateKyberPreKey(): Promise<boolean> {
    return KeyRotationOps.rotateKyberPreKey(this.ctx);
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
    return GroupOps.createGroupSenderKey(this.ctx, this.senderKeyManager, groupId);
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
    return GroupOps.processSenderKeyDistribution(
      this.ctx,
      this.senderKeyManager,
      groupId,
      senderId,
      senderDeviceId,
      message
    );
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
    return GroupOps.encryptGroupMessage(
      this.ctx,
      this.senderKeyManager,
      groupId,
      plaintext,
      this.groupManager
        ? (candidateGroupId) =>
            this.groupManager!.assertGroupSendAllowed(candidateGroupId)
        : undefined
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
    return GroupOps.decryptGroupMessage(
      this.ctx,
      this.senderKeyManager,
      groupId,
      senderId,
      senderDeviceId,
      framedMessage
    );
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
    return GroupOps.rotateGroupSenderKey(
      this.ctx,
      this.senderKeyManager,
      groupId,
      this.config.onGroupSenderKeyRotated
    );
  }

  /**
   * Delete sender key when leaving a group
   *
   * @param groupId - Group identifier
   */
  async deleteGroupSenderKey(groupId: string): Promise<void> {
    return GroupOps.deleteGroupSenderKey(this.ctx, this.senderKeyManager, groupId);
  }

  /**
   * Check if we have a sender key for a group
   *
   * @param groupId - Group identifier
   * @returns True if sender key exists for this device
   */
  async hasGroupSenderKey(groupId: string): Promise<boolean> {
    return GroupOps.hasGroupSenderKey(this.ctx, groupId);
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
    return GroupOps.getGroupSenderKeyDistribution(this.ctx, groupId);
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
    // Do not distribute to self
    if (recipientUserId === this.userId) {
      return;
    }

    // Get or create sender key
    let distribution = await this.getGroupSenderKeyDistribution(groupId);
    if (!distribution) {
      const result = await this.createGroupSenderKey(groupId);
      distribution = result.distributionMessage;
    }

    // Create the distribution payload using ProtoContentData format
    // senderKeyDistributionMessage is a string field containing JSON-encoded SKDM data
    const payload = this.contentAdapter.serializeSenderKeyDistributionText(groupId, distribution);

    // Send via pairwise encryption (SESAME handles multi-device)
    await this.send(recipientUserId, payload);

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
    // Filter out self
    const recipients = memberUserIds.filter((id) => id !== this.userId);

    if (recipients.length === 0) {
      this.logger.debug('No recipients for sender key distribution', {
        category: 'E2EE',
        data: { groupId },
      });
      return;
    }

    // Distribute to each member
    const results = await Promise.allSettled(
      recipients.map((userId) => this.distributeSenderKeyToUser(groupId, userId))
    );

    // Count successes and failures
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;

    this.logger.debug('Distributed sender key to group', {
      category: 'E2EE',
      data: { groupId, succeeded, failed, total: recipients.length },
    });

    // If all failed, throw an error
    if (failed === recipients.length) {
      throw new EncryptionError(
        `Failed to distribute sender key to any group members`,
        EncryptionErrorCode.ENCRYPTION_FAILED
      );
    }
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
    return this.senderKeyManager.getStats(groupId, senderId, senderDeviceId);
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
      this.groups,
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
    return GroupOps.getGroupState(this.ctx, this.groups, groupId);
  }

  /**
   * Sync group state from server.
   */
  async syncGroup(groupId: GroupId): Promise<DecryptedGroup> {
    return GroupOps.syncGroup(this.ctx, this.groups, groupId);
  }

  /**
   * Add a member to a group.
   */
  async addGroupMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    member: GroupMemberInput
  ): Promise<void> {
    return GroupOps.addGroupMember(
      this.ctx,
      this.groups,
      groupId,
      editorAci,
      member
    );
  }

  /** Accept this client's pending profile-key invitation. */
  async acceptGroupMemberInvitation(groupId: GroupId): Promise<void> {
    return GroupOps.acceptGroupMemberInvitation(this.ctx, this.groups, groupId);
  }

  /**
   * Decline this account's ACI- or PNI-keyed pending invitation.
   */
  async declineGroupMemberInvitation(
    groupId: GroupId,
    identity: 'aci' | 'pni' = 'aci'
  ): Promise<void> {
    return GroupOps.declineGroupMemberInvitation(
      this.ctx,
      this.groups,
      groupId,
      identity
    );
  }

  /**
   * Remove a member from a group. Triggers sender key rotation.
   */
  async removeGroupMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    targetAci: Uint8Array
  ): Promise<void> {
    return GroupOps.removeGroupMember(this.ctx, this.groups, groupId, editorAci, targetAci);
  }

  /**
   * Leave a group.
   */
  async leaveGroup(groupId: GroupId, userAci: Uint8Array): Promise<void> {
    return GroupOps.leaveGroup(this.ctx, this.groups, groupId, userAci);
  }

  /**
   * Update a group's title.
   */
  async updateGroupTitle(groupId: GroupId, editorAci: Uint8Array, title: string): Promise<void> {
    return GroupOps.updateGroupTitle(this.ctx, this.groups, groupId, editorAci, title);
  }

  /**
   * Update a group's description.
   */
  async updateGroupDescription(
    groupId: GroupId,
    editorAci: Uint8Array,
    description: string
  ): Promise<void> {
    return GroupOps.updateGroupDescription(
      this.ctx,
      this.groups,
      groupId,
      editorAci,
      description
    );
  }

  /**
   * Update a group's access control.
   */
  async updateGroupAccessControl(
    groupId: GroupId,
    editorAci: Uint8Array,
    updates: Partial<AccessControl>
  ): Promise<void> {
    return GroupOps.updateGroupAccessControl(
      this.ctx,
      this.groups,
      groupId,
      editorAci,
      updates
    );
  }

  /**
   * Create an invite link for a group.
   */
  async createGroupInviteLink(groupId: GroupId, editorAci: Uint8Array): Promise<string> {
    return GroupOps.createGroupInviteLink(this.ctx, this.groups, groupId, editorAci);
  }

  /**
   * Join a group via invite link.
   */
  async joinGroupViaInviteLink(
    url: string,
    userAci: Uint8Array,
    userProfileKey: Uint8Array
  ): Promise<{ groupId: GroupId; status: 'joined' | 'pending_approval' }> {
    return GroupOps.joinGroupViaInviteLink(this.ctx, this.groups, url, userAci, userProfileKey);
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
