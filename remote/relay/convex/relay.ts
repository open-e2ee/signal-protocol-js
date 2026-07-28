/**
 * ConvexSignalProtocolRelayServer
 *
 * Implementation of ISignalProtocolRelayServer using the Signal Protocol Convex component.
 * Zero-knowledge server - all content is opaque ciphertext.
 *
 * Uses the signal component's 16-table schema.
 *
 * ## Component API Access Pattern
 *
 * This file consumes typed, app-injected API references for the Signal Protocol
 * component's functions. The app-level wrappers are defined in:
 * - convex/signal/keys.ts
 * - convex/signal/devices.ts
 * - convex/signal/messages.ts
 * - convex/signal/provisioning.ts
 *
 */

import type { ConvexReactClient } from 'convex/react';
import type { ConvexHttpClient } from 'convex/browser';
import { ConvexClient as BrowserConvexClient } from 'convex/browser';
import type { ApiFromModules } from 'convex/server';
import type { defineConvexSignalProtocolBackend } from './backend';
import type {
  ISignalProtocolRelayServer,
  Envelope,
  SealedSenderAuth,
  DeviceInfo,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle,
  EcSignedPreKeyUpload,
  KemLastResortPreKeyUpload,
  Unsubscribe,
  GroupMemberDevice,
  GroupChangeEntry,
  GroupChangePage,
  RetryRequest,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  IRelayGroupServer,
} from '../types';
import { RetryReason } from '../../../internal/sesame/types';

import type { PublicKey, Signature } from '../../../keys/branded';
import type { CompositeIdentityV1, IdentityType } from '../../../keys/types';
import { decodeCompositeIdentityV1, encodeCompositeIdentityV1 } from '../../../keys/identity';
import type { GroupAuthorization } from '../../../internal/groups/manager';
import { SealedSenderAuthError } from '../../../types/errors';
import { resolveSignalProtocolLogger, type ILogger } from '../../../logger';
import { ConvexGroupServer } from './group-server';

/**
 * Polling interval for retry request subscription (in milliseconds).
 * Used as fallback when SubscriptionFactory is not provided.
 */
export {};
const RETRY_POLL_INTERVAL_MS = 2000;

/**
 * Polling interval for message subscription (in milliseconds).
 * Used as fallback when push-based subscription is not available.
 */
const MESSAGE_POLL_INTERVAL_MS = 2000;

/**
 * Idle threshold for message batch detection (milliseconds).
 * When no new messages arrive for this duration, the batch is considered complete.
 */
const MESSAGE_IDLE_THRESHOLD_MS = 500;

/**
 * Maximum batch window before forced flush (milliseconds).
 * Prevents indefinite batching if messages keep arriving.
 */
const MAX_BATCH_WINDOW_MS = 5000;

/**
 * Whether a rejection is the component's structured `UNAUTHORIZED`.
 *
 * Reads the `ConvexError` payload rather than matching on the message text.
 * A substring test for `'Unauthorized'` was wrong in both directions: any
 * unrelated failure whose message happened to contain the word downgraded a
 * sealed send to identified delivery — disclosing the sender to the relay to
 * work around an error that was never an authorization failure — while a
 * genuine `code: 'UNAUTHORIZED'` rejection whose message did not spell the
 * word went undetected and surfaced as a hard send failure.
 */
function isUnauthorizedRejection(error: unknown): boolean {
  const data =
    error !== null && typeof error === 'object' && 'data' in error
      ? (error as { data?: { code?: string } }).data
      : undefined;
  return data?.code === 'UNAUTHORIZED';
}

/**
 * Return type for retry request queries.
 * Matches the shape returned by getPendingRetryRequests.
 */
interface RetryRequestResult {
  id: string;
  requesterUserId: string;
  requesterDeviceId: number;
  originalSenderUserId: string;
  originalSenderDeviceId: number;
  failedTimestamp: number;
  timestamp: number;
  reason: string;
}

/**
 * Either ConvexReactClient or ConvexHttpClient can be used.
 * This allows the relay to work in both React contexts and background tasks.
 */
type ConvexClient = ConvexReactClient | ConvexHttpClient;

type SignalProtocolBackend = ReturnType<
  typeof defineConvexSignalProtocolBackend
>;

/**
 * The `api.signal.*` shape Convex code-generates for an app whose
 * `convex/signal/<namespace>.ts` modules re-export the matching namespace bag
 * from {@link defineConvexSignalProtocolBackend}.
 */
type SignalProtocolBackendApi = ApiFromModules<{
  messages: SignalProtocolBackend['messages'];
  devices: SignalProtocolBackend['devices'];
  keys: SignalProtocolBackend['keys'];
  certificates: SignalProtocolBackend['certificates'];
  provisioning: SignalProtocolBackend['provisioning'];
  groups: SignalProtocolBackend['groups'];
  zkAuth: SignalProtocolBackend['zkAuth'];
}>;

/**
 * The app-side function references this adapter calls.
 *
 * Every reference carries the argument and return types Convex derives from
 * the component's own validators, so a call site that disagrees with the
 * component fails to compile here rather than at runtime in the deployment.
 * The types are *derived* from {@link defineConvexSignalProtocolBackend}
 * rather than restated, which is what makes the check meaningful — a
 * hand-written contract can drift from the functions it describes, and this
 * one previously had.
 *
 * `groups` and `zkAuth` are optional: a deployment that does not install the
 * group namespaces still satisfies the rest of the relay surface.
 */
export interface ConvexSignalProtocolRelayApi {
  messages: SignalProtocolBackendApi['messages'];
  devices: SignalProtocolBackendApi['devices'];
  keys: SignalProtocolBackendApi['keys'];
  certificates: SignalProtocolBackendApi['certificates'];
  provisioning: SignalProtocolBackendApi['provisioning'];
  groups?: SignalProtocolBackendApi['groups'];
  zkAuth?: SignalProtocolBackendApi['zkAuth'];
}

export interface ConvexSignalProtocolRelayOptions {
  currentUserId?: string;
  getAuthToken?: () => Promise<string | null>;
  logger?: ILogger;
}

/**
 * ConvexSignalProtocolRelayServer - Implementation of ISignalProtocolRelayServer
 *
 * Uses the Convex Signal Protocol component for the 16-table relay schema.
 *
 * @example
 * ```typescript
 * import { ConvexReactClient } from 'convex/react';
 * import { ConvexSignalProtocolRelayServer } from './relay';
 *
 * const convex = new ConvexReactClient(process.env.CONVEX_URL!);
 * const relay = new ConvexSignalProtocolRelayServer(convex, convexSignalProtocolRelayApi, {
 *   currentUserId: 'current-user-id',
 * });
 *
 * // Subscribe to incoming envelopes
 * const unsubscribe = relay.subscribe(userId, deviceId, (envelope) => {
 *   // Decrypt and process
 * });
 *
 * // Send encrypted envelope
 * await relay.send({
 *   targetUserId: 'bob',
 *   targetDeviceId: 1,
 *   senderUserId: 'alice',
 *   senderDeviceId: 1,
 *   ciphertext: encryptedBytes,
 *   messageType: 'ciphertext',
 * });
 * ```
 */
export class ConvexSignalProtocolRelayServer implements ISignalProtocolRelayServer {
  private subscriptions: Map<string, () => void> = new Map();
  private subscriptionClient: BrowserConvexClient | null = null;
  private currentUserId?: string;
  private getAuthToken?: () => Promise<string | null>;
  private readonly logger: Required<ILogger>;
  readonly groupServer?: IRelayGroupServer;

  /**
   * Create a new ConvexSignalProtocolRelayServer.
   *
   * @param convex - Convex client (React or HTTP)
   * @param api - Generated Convex Signal Protocol API map for queries and mutations
   * @param options.currentUserId - Current user's ID for ownership-scoped relay operations
   * @param options.getAuthToken - Optional auth token getter for push-based subscriptions.
   *   When provided, creates an internal ConvexClient with WebSocket push.
   * @param options.logger - Optional logger for relay operations
   */
  constructor(
    private convex: ConvexClient,
    private api: ConvexSignalProtocolRelayApi,
    options: ConvexSignalProtocolRelayOptions = {}
  ) {
    this.currentUserId = options.currentUserId;
    this.getAuthToken = options.getAuthToken;
    this.logger = resolveSignalProtocolLogger(options.logger);
    if (api.groups && api.zkAuth) {
      this.groupServer = {
        server: new ConvexGroupServer(convex, api.groups),
        issueAuthCredential: (userId) =>
          this.issueAuthCredential(userId),
        issueProfileKeyCredential: (_userId, profileKey) =>
          this.issueProfileKeyCredential(profileKey),
      };
    }
  }

  /**
   * Get or create the internal subscription client for push-based updates.
   * Created lazily on first use to avoid unnecessary connections.
   */
  private async getSubscriptionClient(): Promise<BrowserConvexClient | null> {
    if (this.subscriptionClient) return this.subscriptionClient;

    const url = process.env.EXPO_PUBLIC_CONVEX_URL;
    if (!url || !this.getAuthToken) return null;

    try {
      this.subscriptionClient = new BrowserConvexClient(url);

      // Re-fetch token on each auth request (handles token expiry)
      this.subscriptionClient.setAuth(async () => {
        return (await this.getAuthToken?.()) ?? null;
      });

      this.logger.debug('Created internal subscription client for push-based updates', {
        category: 'E2EE',
      });

      return this.subscriptionClient;
    } catch (error) {
      this.logger.warn('Failed to create subscription client, will use polling fallback', {
        category: 'E2EE',
        error: error as Error,
      });
      return null;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // ENVELOPE DELIVERY
  // ════════════════════════════════════════════════════════════════════════════

  async send(envelope: Envelope): Promise<{ messageId: string; serverTimestamp: number }> {
    const ciphertext =
      typeof envelope.ciphertext === 'string'
        ? envelope.ciphertext
        : this.uint8ArrayToBase64(envelope.ciphertext);

    const result = await this.convex.mutation(this.api.messages.send, {
      targetUserId: envelope.targetUserId,
      targetDeviceId: envelope.targetDeviceId,
      // senderUserId derived server-side from JWT auth
      senderDeviceId: envelope.senderDeviceId,
      ciphertext,
      messageType: envelope.messageType,
      urgent: envelope.urgent,
      ephemeral: envelope.ephemeral,
      timestamp: envelope.timestamp,
      clientMessageId: envelope.clientMessageId,
      // Relay-side stale-device detection validates the registration ID only.
      // Signed-prekey staleness is detected client-side during authenticated
      // decryption and recovery.
      recipientRegistrationId: envelope.recipientRegistrationId,
    });

    return result;
  }

  /**
   * Subscribe to incoming envelopes for this device.
   *
   * When getAuthToken is provided (via constructor), uses WebSocket push
   * for instant delivery (~50ms). Otherwise, falls back to polling every 2 seconds.
   *
   * Supports optional batching callbacks for notification coalescing.
   * When messages arrive rapidly, onBatchStart is called once at the start,
   * and onBatchEnd is called after an idle period (no new messages for 500ms).
   *
   * @param userId - Current user ID
   * @param deviceId - This device's ID (1-5)
   * @param onEnvelope - Callback for each incoming envelope
   * @param options - Optional batching callbacks
   * @returns Unsubscribe function
   *
   */
  subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: {
      onBatchStart?: () => void;
      onBatchEnd?: () => void;
    }
  ): Unsubscribe {
    // Use push-based subscription if auth token getter is available
    if (this.getAuthToken) {
      return this.subscribeMessagesPush(userId, deviceId, onEnvelope, options);
    }

    // Fallback to polling for ConvexHttpClient or when no auth token getter provided
    return this.subscribeMessagesPolling(userId, deviceId, onEnvelope, options);
  }

  /**
   * Push-based message subscription using internal ConvexClient.
   * Provides instant delivery via WebSocket with idle-detection batching.
   *
   * Batching behavior:
   * - Messages are queued until idle (no new messages for MESSAGE_IDLE_THRESHOLD_MS)
   * - onBatchStart called when first message arrives
   * - onBatchEnd called when batch is flushed
   * - Forced flush after MAX_BATCH_WINDOW_MS to prevent indefinite batching
   */
  private subscribeMessagesPush(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: {
      onBatchStart?: () => void;
      onBatchEnd?: () => void;
    }
  ): Unsubscribe {
    const key = `messages:${userId}:${deviceId}`;
    const processedIds = new Set<string>();
    let clientUnsubscribe: (() => void) | null = null;
    let isActive = true;

    // Idle-detection batching state
    let pendingEnvelopes: Envelope[] = [];
    let idleTimer: ReturnType<typeof setTimeout> | null = null;
    let batchStartTime: number | null = null;

    const flushBatch = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = null;

      const batch = pendingEnvelopes;
      pendingEnvelopes = [];
      batchStartTime = null;

      // Deliver all pending envelopes
      for (const envelope of batch) {
        onEnvelope(envelope);
      }

      if (batch.length > 0) {
        options?.onBatchEnd?.();
      }
    };

    const queueEnvelope = (envelope: Envelope) => {
      if (pendingEnvelopes.length === 0) {
        options?.onBatchStart?.();
        batchStartTime = Date.now();
      }

      pendingEnvelopes.push(envelope);

      if (idleTimer) clearTimeout(idleTimer);

      // Force flush if max batch window exceeded
      if (batchStartTime && Date.now() - batchStartTime >= MAX_BATCH_WINDOW_MS) {
        flushBatch();
        return;
      }

      // Set idle timer
      idleTimer = setTimeout(flushBatch, MESSAGE_IDLE_THRESHOLD_MS);
    };

    this.logger.debug('[Relay] Subscription started', {
      category: 'E2EE',
      data: { userId, deviceId },
    });

    // Async initialization - get or create the subscription client
    this.getSubscriptionClient().then((client) => {
      // Check if already unsubscribed before setting up listener
      if (!isActive) {
        return; // Don't set up anything if already cancelled
      }

      if (!client) {
        // Fall back to polling if client creation failed
        this.logger.warn('Subscription client unavailable, falling back to polling', {
          category: 'E2EE',
        });
        const pollingUnsub = this.subscribeMessagesPolling(userId, deviceId, onEnvelope, options);
        this.subscriptions.set(key, pollingUnsub);
        return;
      }

      clientUnsubscribe = client.onUpdate(
        this.api.messages.getPendingMessages,
        { deviceId },
        (messages) => {
          // Guard against callbacks after unsubscribe
          if (!isActive) return;

          for (const msg of messages) {
            if (processedIds.has(msg.id)) continue;
            processedIds.add(msg.id);

            queueEnvelope({
              id: msg.id,
              targetUserId: userId,
              targetDeviceId: deviceId,
              senderUserId: msg.senderUserId,
              senderDeviceId: msg.senderDeviceId,
              ciphertext: msg.ciphertext,
              messageType: msg.messageType,
              timestamp: msg.timestamp,
              serverTimestamp: msg.serverTimestamp,
            });
          }

          // Cleanup processed IDs no longer in pending
          const currentIds = new Set(messages.map((m: { id: string }) => m.id));
          for (const id of processedIds) {
            if (!currentIds.has(id)) processedIds.delete(id);
          }
        }
      );

      // If unsubscribe was called during init, clean up now
      if (!isActive && clientUnsubscribe) {
        clientUnsubscribe();
        clientUnsubscribe = null;
      }
    });

    // Return unsubscribe function that cleans up
    const wrappedUnsubscribe = () => {
      isActive = false;
      flushBatch(); // Flush any pending on unsubscribe
      clientUnsubscribe?.();
      this.subscriptions.delete(key);
    };

    this.subscriptions.set(key, wrappedUnsubscribe);
    return wrappedUnsubscribe;
  }

  /**
   * Polling-based message subscription fallback.
   * Used when no getAuthToken is available or subscription client creation fails.
   *
   * NOTE: This has ~2 second latency. Use push-based subscription for production.
   */
  private subscribeMessagesPolling(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: {
      onBatchStart?: () => void;
      onBatchEnd?: () => void;
    }
  ): Unsubscribe {
    const key = `messages:${userId}:${deviceId}`;
    let isActive = true;
    let lastMessageIds = new Set<string>();

    this.logger.debug('Starting polling-based message subscription (fallback)', {
      category: 'E2EE',
      data: { userId, deviceId, pollIntervalMs: MESSAGE_POLL_INTERVAL_MS },
    });

    // Polling fallback for non-React contexts
    const poll = async () => {
      if (!isActive) return;

      try {
        const messages = await this.convex.query(this.api.messages.getPendingMessages, {
          deviceId,
        });

        // Track if we have new messages for batching
        const newMessages: Envelope[] = [];

        for (const msg of messages) {
          // Only process new messages
          if (!lastMessageIds.has(msg.id)) {
            lastMessageIds.add(msg.id);
            newMessages.push({
              id: msg.id,
              targetUserId: userId,
              targetDeviceId: deviceId,
              senderUserId: msg.senderUserId,
              senderDeviceId: msg.senderDeviceId,
              ciphertext: msg.ciphertext,
              messageType: msg.messageType,
              timestamp: msg.timestamp,
              serverTimestamp: msg.serverTimestamp,
            });
          }
        }

        // Deliver with batch callbacks (polling knows batch boundaries upfront)
        if (newMessages.length > 0) {
          options?.onBatchStart?.();
          for (const envelope of newMessages) {
            onEnvelope(envelope);
          }
          options?.onBatchEnd?.();
        }

        // Update tracked IDs (remove ones no longer in pending)
        const currentIds = new Set<string>(messages.map((m: { id: string }) => m.id));
        lastMessageIds = currentIds;
      } catch (error) {
        this.logger.error('Error polling messages', {
          category: 'E2EE',
          error: error as Error,
        });
      }

      // Poll every 2 seconds
      if (isActive) {
        setTimeout(poll, MESSAGE_POLL_INTERVAL_MS);
      }
    };

    // Start polling
    poll();

    const unsubscribe = () => {
      isActive = false;
      this.subscriptions.delete(key);
    };

    this.subscriptions.set(key, unsubscribe);

    return unsubscribe;
  }

  async markDelivered(messageId: string): Promise<void> {
    await this.convex.mutation(this.api.messages.markDelivered, {
      messageId,
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // DEVICE REGISTRY
  // ════════════════════════════════════════════════════════════════════════════

  async getDevices(userId: string): Promise<DeviceInfo[]> {
    const devices = await this.convex.query(this.api.devices.getDevices, {
      userId,
    });

    return devices;
  }

  async registerDevice(_userId: string, device: DeviceRegistration): Promise<number> {
    const result = await this.convex.mutation(this.api.devices.registerDevice, {
      // userId derived server-side from JWT auth
      deviceId: device.deviceId,
      encryptedDeviceName: device.encryptedDeviceName,
      deviceType: device.deviceType,
      // Note: Push tokens are managed separately via convex/signal/push.ts
    });

    return result.deviceId;
  }

  async removeDevice(_userId: string, deviceId: number): Promise<void> {
    await this.convex.mutation(this.api.devices.removeDevice, {
      // userId derived server-side from JWT auth
      deviceId,
    });
  }

  // Note: updatePushToken removed - push tokens are managed by convex/signal/push.ts
  // using @convex-dev/expo-push-notifications with device-aware composite keys.

  async markDeviceConnected(deviceId: number): Promise<void> {
    await this.convex.mutation(this.api.devices.markDeviceConnected, {
      deviceId,
    });
  }

  async markDeviceDisconnected(deviceId: number): Promise<void> {
    await this.convex.mutation(this.api.devices.markDeviceDisconnected, {
      deviceId,
    });
  }

  async heartbeat(deviceId: number): Promise<void> {
    await this.convex.mutation(this.api.devices.presenceHeartbeat, {
      deviceId,
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // IDENTITY KEYS
  // ════════════════════════════════════════════════════════════════════════════

  async provisionIdentityKey(request: AccountIdentityProvisioning): Promise<void> {
    const { userId, deviceId, identity, registrationId, identityType = 'aci' } = request;
    await this.convex.mutation(this.api.keys.uploadIdentityKey, {
      mode: 'provision',
      userId,
      deviceId,
      compositeIdentity: this.uint8ArrayToBase64(encodeCompositeIdentityV1(identity)),
      registrationId,
      identityType,
    });
  }

  async rotateIdentityKey(request: AccountIdentityRotation): Promise<void> {
    const {
      userId,
      deviceId,
      identity,
      registrationId,
      identityType = 'aci',
      expectedCurrentCommitment,
    } = request;
    await this.convex.mutation(this.api.keys.uploadIdentityKey, {
      mode: 'rotate',
      userId,
      deviceId,
      compositeIdentity: this.uint8ArrayToBase64(encodeCompositeIdentityV1(identity)),
      registrationId,
      identityType,
      expectedCurrentCommitment: this.uint8ArrayToBase64(expectedCurrentCommitment),
    });
  }

  async getIdentityKey(
    userId: string,
    identityType?: IdentityType
  ): Promise<CompositeIdentityV1 | null> {
    const encodedIdentity = await this.convex.query(this.api.keys.getIdentityKey, {
      userId,
      identityType: identityType ?? 'aci',
    });

    if (!encodedIdentity) {
      return null;
    }

    return decodeCompositeIdentityV1(this.base64ToUint8Array(encodedIdentity));
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PREKEY MANAGEMENT
  // ════════════════════════════════════════════════════════════════════════════

  async uploadPreKeys(
    userId: string,
    deviceId: number,
    keys: PreKeyUpload[],
    identityType?: IdentityType
  ): Promise<void> {
    await this.convex.mutation(this.api.keys.uploadPreKeys, {
      userId,
      deviceId,
      identityType: identityType ?? 'aci',
      keys: keys.map((key) => ({
        type: key.type,
        keyId: key.keyId,
        publicKey: key.publicKey,
        signature: key.signature,
      })),
    });
  }

  /**
   * Fetch prekey bundle for session establishment.
   *
   * Rate limited to 10 fetches per minute per fetcher-target pair.
   * Fetcher identity is always derived from auth on the server side
   * (matches the relay application format).
   *
   * @param userId - Target user ID
   * @param deviceId - Target device ID
   * @param _fetcherUserId - Deprecated, ignored. Fetcher derived from auth server-side.
   */
  async fetchPreKeyBundle(
    userId: string,
    deviceId: number,
    _fetcherUserId?: string,
    identityType?: IdentityType
  ): Promise<PreKeyBundle | null> {
    const bundle = await this.convex.mutation(this.api.keys.fetchPreKeyBundle, {
      userId,
      deviceId,
      identityType: identityType ?? 'aci',
    });

    if (!bundle) {
      return null;
    }

    // Cast to branded types - data crosses wire boundary as plain strings
    // Adapters handle the casting internally so callers don't need to
    return {
      registrationId: bundle.registrationId,
      deviceId: bundle.deviceId,
      identity: decodeCompositeIdentityV1(this.base64ToUint8Array(bundle.compositeIdentity)),
      ecSignedPreKey: {
        keyId: bundle.ecSignedPreKey.keyId,
        publicKey: bundle.ecSignedPreKey.publicKey as PublicKey,
        signature: bundle.ecSignedPreKey.signature as Signature,
      },
      ecOneTimePreKey: bundle.ecOneTimePreKey
        ? {
            keyId: bundle.ecOneTimePreKey.keyId,
            publicKey: bundle.ecOneTimePreKey.publicKey as PublicKey,
          }
        : null,
      kemLastResortPreKey: bundle.kemLastResortPreKey
        ? {
            keyId: bundle.kemLastResortPreKey.keyId,
            publicKey: bundle.kemLastResortPreKey.publicKey as PublicKey,
            signature: bundle.kemLastResortPreKey.signature as Signature,
          }
        : null,
      kemOneTimePreKey: bundle.kemOneTimePreKey
        ? {
            keyId: bundle.kemOneTimePreKey.keyId,
            publicKey: bundle.kemOneTimePreKey.publicKey as PublicKey,
            signature: bundle.kemOneTimePreKey.signature as Signature,
          }
        : null,
    };
  }

  async getPreKeyCount(
    userId: string,
    deviceId: number,
    type: 'ec' | 'kem',
    identityType?: IdentityType
  ): Promise<number> {
    return await this.convex.query(this.api.keys.getPreKeyCount, {
      userId,
      deviceId,
      type,
      identityType: identityType ?? 'aci',
    });
  }

  async clearStaleKemPreKeys(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ cleared: number }> {
    return await this.convex.mutation(this.api.keys.clearStaleKemPreKeys, {
      userId,
      deviceId,
      identityType: identityType ?? 'aci',
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CONVENIENCE METHODS (Key Rotation)
  // ════════════════════════════════════════════════════════════════════════════

  async uploadEcSignedPreKey(
    userId: string,
    ecSignedPreKey: EcSignedPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void> {
    await this.convex.mutation(this.api.keys.uploadEcSignedPreKey, {
      userId,
      identityType: identityType ?? 'aci',
      ecSignedPreKey: {
        id: ecSignedPreKey.keyId,
        deviceId: ecSignedPreKey.deviceId,
        publicKey: ecSignedPreKey.publicKey,
        signature: ecSignedPreKey.signature,
        timestamp: ecSignedPreKey.timestamp,
      },
    });
  }

  async uploadKemLastResortPreKey(
    userId: string,
    kemLastResortPreKey: KemLastResortPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void> {
    await this.convex.mutation(this.api.keys.uploadKemLastResortPreKey, {
      userId,
      identityType: identityType ?? 'aci',
      kemLastResortPreKey: {
        id: kemLastResortPreKey.keyId,
        deviceId: kemLastResortPreKey.deviceId,
        publicKey: kemLastResortPreKey.publicKey,
        signature: kemLastResortPreKey.signature,
        timestamp: kemLastResortPreKey.timestamp,
      },
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // GROUP MEMBER RESOLUTION (Sender Keys) — local-first; no membership map
  // ════════════════════════════════════════════════════════════════════════════

  async getActiveDevices(userId: string): Promise<GroupMemberDevice[]> {
    const devices = await this.convex.query(this.api.messages.getActiveDevices, {
      userId,
    });

    return devices;
  }

  // ════════════════════════════════════════════════════════════════════════════
  // SEALED SENDER (Anonymous Delivery)
  // ════════════════════════════════════════════════════════════════════════════

  async fetchSenderCertificate(deviceId: number): Promise<string> {
    return await this.convex.mutation(this.api.certificates.issueSenderCertificate, {
      deviceId,
    });
  }

  async sendUnidentified(
    envelope: Envelope,
    auth: SealedSenderAuth
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    const ciphertext =
      typeof envelope.ciphertext === 'string'
        ? envelope.ciphertext
        : this.uint8ArrayToBase64(envelope.ciphertext);

    try {
      if (auth.type === 'groupSendToken') {
        // The server verifies the ZK endorsement token against the claimed
        // recipient ACI before it reads any account, so the claim rides
        // along with the token.
        const claimed = auth.recipientAciBytes.get(envelope.targetUserId);
        if (!claimed) {
          throw new SealedSenderAuthError();
        }
        return await this.convex.mutation(this.api.messages.sendUnidentified, {
          targetUserId: envelope.targetUserId,
          targetDeviceId: envelope.targetDeviceId,
          targetAciBytes: claimed.buffer.slice(
            claimed.byteOffset,
            claimed.byteOffset + claimed.byteLength
          ) as ArrayBuffer,
          ciphertext,
          timestamp: envelope.timestamp,
          clientMessageId: envelope.clientMessageId,
          groupSendToken: auth.groupSendToken.buffer.slice(
            auth.groupSendToken.byteOffset,
            auth.groupSendToken.byteOffset + auth.groupSendToken.byteLength
          ) as ArrayBuffer,
        });
      }

      // Access key path (profile-key-derived UAK)
      return await this.convex.mutation(this.api.messages.sendUnidentified, {
        targetUserId: envelope.targetUserId,
        targetDeviceId: envelope.targetDeviceId,
        ciphertext,
        timestamp: envelope.timestamp,
        clientMessageId: envelope.clientMessageId,
        unidentifiedAccessKey: auth.unidentifiedAccessKey,
      });
    } catch (error) {
      // Convert an authorization rejection into the typed error the cipher
      // watches for when deciding to retry on the identified path.
      if (isUnauthorizedRejection(error)) {
        throw new SealedSenderAuthError(error instanceof Error ? error : undefined);
      }
      throw error;
    }
  }

  /**
   * Send a V2 multi-recipient sealed sender message.
   *
   * Parses the V2 binary blob client-side, then sends structured
   * per-recipient data to the Convex mutation for server-side fan-out.
   *
   * @param sentMessageBase64 - Base64-encoded V2 multi-recipient binary blob
   * @param auth - Sealed sender authentication (access key or group send token)
   * @param timestamp - Client timestamp for message identification
   * @param recipientUserIds - Original user IDs in same order as binary recipients
   */
  async sendMultiRecipientUnidentified(
    sentMessageBase64: string,
    auth: SealedSenderAuth,
    timestamp: number,
    recipientUserIds?: string[],
    clientMessageId?: string
  ): Promise<{ messageId: string; serverTimestamp: number; uuids404: string[] }> {
    const { base64ToBytes, bytesToBase64 } = await import('../../../internal/crypto');
    const { asBase64 } = await import('../../../types/utils');
    const { deserializeSentMessage } =
      await import('../../../internal/protocol/sealed-sender/v2-binary');

    const binaryBlob = base64ToBytes(asBase64(sentMessageBase64));
    const parsed = deserializeSentMessage(binaryBlob);

    // Flatten: each recipient can have MULTIPLE devices
    const flatRecipients = parsed.recipients.flatMap((r, i) =>
      r.devices.map((d) => ({
        userId: recipientUserIds?.[i] ?? r.serviceId,
        deviceId: d.deviceId,
        registrationId: d.registrationId,
        encryptedMessageKeyBase64: bytesToBase64(r.encryptedMessageKey),
        authenticationTagBase64: bytesToBase64(r.authenticationTag),
      }))
    );

    try {
      if (auth.type === 'groupSendToken') {
        // Attach the claimed ACI to each recipient: the server verifies the
        // token against the claims before it reads any account.
        const claimedRecipients = flatRecipients.map((recipient) => {
          const claimed = auth.recipientAciBytes.get(recipient.userId);
          if (!claimed) {
            throw new SealedSenderAuthError();
          }
          return {
            ...recipient,
            aciBytes: claimed.buffer.slice(
              claimed.byteOffset,
              claimed.byteOffset + claimed.byteLength
            ) as ArrayBuffer,
          };
        });
        return await this.convex.mutation(this.api.messages.sendMultiRecipientUnidentified, {
          recipients: claimedRecipients,
          ephemeralPublicBase64: bytesToBase64(parsed.ephemeralPublic),
          messageCiphertextBase64: bytesToBase64(parsed.messageCiphertext),
          timestamp,
          clientMessageId,
          groupSendToken: auth.groupSendToken.buffer.slice(
            auth.groupSendToken.byteOffset,
            auth.groupSendToken.byteOffset + auth.groupSendToken.byteLength
          ) as ArrayBuffer,
        });
      }

      return await this.convex.mutation(this.api.messages.sendMultiRecipientUnidentified, {
        recipients: flatRecipients,
        ephemeralPublicBase64: bytesToBase64(parsed.ephemeralPublic),
        messageCiphertextBase64: bytesToBase64(parsed.messageCiphertext),
        timestamp,
        clientMessageId,
        unidentifiedAccessKey: auth.unidentifiedAccessKey,
      });
    } catch (error) {
      if (isUnauthorizedRejection(error)) {
        throw new SealedSenderAuthError(error instanceof Error ? error : undefined);
      }
      throw error;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // RETRY REQUESTS (SESAME Spec §6.2)
  // ════════════════════════════════════════════════════════════════════════════

  /**
   * Send retry request to the original sender.
   *
   * Called by recipient when decryption fails. The request is stored
   * in the sender's retry request queue for them to process.
   */
  async sendRetryRequest(request: RetryRequest): Promise<void> {
    await this.convex.mutation(this.api.messages.sendRetryRequest, {
      // requesterUserId derived server-side from JWT auth
      requesterDeviceId: request.requesterDeviceId,
      originalSenderUserId: request.originalSenderUserId,
      originalSenderDeviceId: request.originalSenderDeviceId,
      failedTimestamp: request.failedTimestamp,
      timestamp: request.timestamp,
      reason: request.reason,
    });
  }

  /**
   * Subscribe to incoming retry requests for this device.
   *
   * When getAuthToken is provided (via constructor), uses WebSocket push
   * for instant delivery (<100ms). Otherwise, falls back to polling every 2 seconds.
   *
   * @param userId - User ID (original sender)
   * @param deviceId - Device ID
   * @param handler - Callback for each retry request
   * @returns Unsubscribe function
   */
  subscribeRetryRequests(
    userId: string,
    deviceId: number,
    handler: (request: RetryRequest) => Promise<void>
  ): Unsubscribe {
    // Use push-based subscription if auth token getter is available
    if (this.getAuthToken) {
      return this.subscribeRetryRequestsPush(userId, deviceId, handler);
    }

    // Fallback to polling for ConvexHttpClient or when no auth token getter provided
    return this.subscribeRetryRequestsPolling(userId, deviceId, handler);
  }

  /**
   * Push-based subscription using internal ConvexClient.
   * Provides instant delivery via WebSocket.
   */
  private subscribeRetryRequestsPush(
    userId: string,
    deviceId: number,
    handler: (request: RetryRequest) => Promise<void>
  ): Unsubscribe {
    const key = `retry:${userId}:${deviceId}`;
    const processedIds = new Set<string>();
    let clientUnsubscribe: (() => void) | null = null;
    let isActive = true;

    this.logger.debug('Starting push-based retry request subscription', {
      category: 'E2EE',
      data: { userId, deviceId },
    });

    // Async initialization - get or create the subscription client
    this.getSubscriptionClient().then((client) => {
      if (!client || !isActive) {
        // Fall back to polling if client creation failed
        if (isActive) {
          this.logger.warn('Subscription client unavailable, falling back to polling', {
            category: 'E2EE',
          });
          const pollingUnsub = this.subscribeRetryRequestsPolling(userId, deviceId, handler);
          this.subscriptions.set(key, pollingUnsub);
        }
        return;
      }

      clientUnsubscribe = client.onUpdate(
        this.api.messages.getPendingRetryRequests,
        { deviceId },
        async (requests: RetryRequestResult[]) => {
          for (const req of requests) {
            // Skip already processed requests
            if (processedIds.has(req.id)) {
              continue;
            }

            // Mark as processing to prevent duplicate handling
            processedIds.add(req.id);

            try {
              await handler({
                requesterUserId: req.requesterUserId,
                requesterDeviceId: req.requesterDeviceId,
                originalSenderUserId: req.originalSenderUserId,
                originalSenderDeviceId: req.originalSenderDeviceId,
                failedTimestamp: req.failedTimestamp,
                timestamp: req.timestamp,
                reason: req.reason as RetryReason,
              });
            } catch (handlerError) {
              // Handler failed — safe to retry on next update
              processedIds.delete(req.id);
              this.logger.error('Error in retry request handler', {
                category: 'E2EE',
                error: handlerError as Error,
                data: { requestId: req.id },
              });
              continue;
            }

            // Handler succeeded — mark as handled on server (best-effort)
            try {
              await this.convex.mutation(this.api.messages.markRetryRequestHandled, {
                requestId: req.id,
              });
              this.logger.debug('Retry request handled successfully', {
                category: 'E2EE',
                data: { requestId: req.id, failedTimestamp: req.failedTimestamp },
              });
            } catch (markError) {
              // Mark failed but handler already ran — keep in processedIds to prevent duplicate
              this.logger.warn('Failed to mark retry request as handled (handler already ran)', {
                category: 'E2EE',
                data: { requestId: req.id },
                error: markError as Error,
              });
            }
          }

          // Cleanup: remove IDs no longer in pending results (already deleted from server)
          const currentIds = new Set(requests.map((r) => r.id));
          for (const id of processedIds) {
            if (!currentIds.has(id)) {
              processedIds.delete(id);
            }
          }
        }
      );
    });

    // Return unsubscribe function that cleans up
    const wrappedUnsubscribe = () => {
      isActive = false;
      clientUnsubscribe?.();
      this.subscriptions.delete(key);
    };

    this.subscriptions.set(key, wrappedUnsubscribe);
    return wrappedUnsubscribe;
  }

  /**
   * Polling-based subscription fallback.
   * Used when no getAuthToken is available or subscription client creation fails.
   *
   * NOTE: This has ~2 second latency. Use push-based subscription for production.
   */
  private subscribeRetryRequestsPolling(
    userId: string,
    deviceId: number,
    handler: (request: RetryRequest) => Promise<void>
  ): Unsubscribe {
    const key = `retry:${userId}:${deviceId}`;
    let isActive = true;

    // Use stable set that accumulates processed IDs (don't replace on each poll)
    // This prevents both duplicate processing and lost requests
    const processedIds = new Set<string>();

    this.logger.debug('Starting polling-based retry request subscription (fallback)', {
      category: 'E2EE',
      data: { userId, deviceId, pollIntervalMs: RETRY_POLL_INTERVAL_MS },
    });

    const poll = async () => {
      if (!isActive) return;

      try {
        const requests = await this.convex.query(this.api.messages.getPendingRetryRequests, {
          deviceId,
        });

        for (const req of requests) {
          // Skip already processed requests
          if (processedIds.has(req.id)) {
            continue;
          }

          // Mark as processing to prevent duplicate handling
          processedIds.add(req.id);

          try {
            await handler({
              requesterUserId: req.requesterUserId,
              requesterDeviceId: req.requesterDeviceId,
              originalSenderUserId: req.originalSenderUserId,
              originalSenderDeviceId: req.originalSenderDeviceId,
              failedTimestamp: req.failedTimestamp,
              timestamp: req.timestamp,
              reason: req.reason as RetryReason,
            });
          } catch (handlerError) {
            // Handler failed — safe to retry on next poll
            processedIds.delete(req.id);
            this.logger.error('Error in retry request handler', {
              category: 'E2EE',
              error: handlerError as Error,
            });
            continue;
          }

          // Handler succeeded — mark as handled on server (best-effort)
          try {
            await this.convex.mutation(this.api.messages.markRetryRequestHandled, {
              requestId: req.id,
            });
          } catch (markError) {
            // Mark failed but handler already ran — keep in processedIds to prevent duplicate
            this.logger.warn('Failed to mark retry request as handled (handler already ran)', {
              category: 'E2EE',
              error: markError as Error,
            });
          }
        }

        // Cleanup: remove IDs no longer in pending results (already deleted from server)
        // This prevents memory leak from accumulating old IDs
        const currentIds = new Set<string>(requests.map((r: { id: string }) => r.id));
        for (const id of processedIds) {
          if (!currentIds.has(id)) {
            processedIds.delete(id);
          }
        }
      } catch (error) {
        this.logger.error('Error polling retry requests', {
          category: 'E2EE',
          error: error as Error,
        });
      }

      // Continue polling
      if (isActive) {
        setTimeout(poll, RETRY_POLL_INTERVAL_MS);
      }
    };

    // Start polling
    poll();

    const unsubscribe = () => {
      isActive = false;
      this.subscriptions.delete(key);
    };

    this.subscriptions.set(key, unsubscribe);
    return unsubscribe;
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PROVISIONING SERVICE (IProvisioningService)
  // ════════════════════════════════════════════════════════════════════════════

  async createProvisioningSession(
    userId: string,
    ephemeralPublicKey: string
  ): Promise<{ sessionId: string }> {
    return await this.convex.mutation(this.api.provisioning.createProvisioningSession, {
      userId,
      ephemeralPublicKey,
    });
  }

  async connectNewDevice(
    sessionId: string,
    ephemeralPublicKey: string,
    deviceMetadata: {
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<void> {
    await this.convex.mutation(this.api.provisioning.connectNewDevice, {
      sessionId,
      ephemeralPublicKey,
      deviceMetadata,
    });
  }

  async sendProvisioningMessage(
    sessionId: string,
    encryptedMessage: string,
    userId?: string
  ): Promise<void> {
    if (!userId && !this.currentUserId) {
      throw new Error('userId required for sendProvisioningMessage');
    }
    await this.convex.mutation(this.api.provisioning.sendProvisioningMessage, {
      userId: userId ?? this.currentUserId!,
      sessionId,
      encryptedMessage,
    });
  }

  async getProvisioningMessage(sessionId: string): Promise<{
    status:
      | 'waiting'
      | 'connected'
      | 'ready'
      | 'linked_pending_ack'
      | 'completed'
      | 'rolled_back'
      | 'expired';
    message: string | null;
    expiresAt: number | null;
  }> {
    // No cast: the reference carries the component's own return validator, so
    // a component change that stops satisfying this signature fails here.
    return await this.convex.query(this.api.provisioning.getProvisioningMessage, {
      sessionId,
    });
  }

  async completeProvisioning(
    sessionId: string,
    deviceMetadata: {
      encryptedDeviceName: ArrayBuffer;
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<{ deviceId: number }> {
    return await this.convex.mutation(this.api.provisioning.completeProvisioning, {
      sessionId,
      deviceMetadata,
    });
  }

  async acknowledgeProvisioning(sessionId: string): Promise<void> {
    await this.convex.mutation(this.api.provisioning.acknowledgeProvisioning, {
      sessionId,
    });
  }

  async rollbackProvisioning(sessionId: string): Promise<void> {
    await this.convex.mutation(this.api.provisioning.rollbackProvisioning, {
      sessionId,
    });
  }

  async deleteProvisioningSession(sessionId: string, userId?: string): Promise<void> {
    if (!userId && !this.currentUserId) {
      throw new Error('userId required for deleteProvisioningSession');
    }
    await this.convex.mutation(this.api.provisioning.deleteProvisioningSession, {
      userId: userId ?? this.currentUserId!,
      sessionId,
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // KEY ROTATION SERVICE (IKeyRotationService)
  // ════════════════════════════════════════════════════════════════════════════

  async getEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ keyId: number; createdAt: number; expiresAt: number; publicKey: string } | null> {
    const metadata = await this.convex.query(this.api.keys.getEcSignedPreKeyMetadata, {
      userId,
      deviceId,
      identityType: identityType ?? 'aci',
    });
    return metadata;
  }

  async getKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ keyId: number; createdAt: number; expiresAt: number; publicKey: string } | null> {
    const metadata = await this.convex.query(this.api.keys.getKemLastResortPreKeyMetadata, {
      userId,
      deviceId,
      identityType: identityType ?? 'aci',
    });
    return metadata;
  }

  // ════════════════════════════════════════════════════════════════════════════
  // GROUP STATE (encrypted, server-opaque)
  // ════════════════════════════════════════════════════════════════════════════

  async createGroupState(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void> {
    const { groups } = this.requireGroupServerApi();
    await this.convex.mutation(groups.createGroup, {
      groupId: this.toBytes(groupId),
      encryptedState: this.toBytes(encryptedState),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
  }

  async getGroupState(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number
  ): Promise<{
    encryptedState: Uint8Array;
    version: number;
    baselineSignature: Uint8Array;
  } | null> {
    const { groups } = this.requireGroupServerApi();
    const result = await this.convex.query(groups.getGroup, {
      groupId: this.toBytes(groupId),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
      version,
    });
    if (!result) return null;
    return {
      encryptedState: new Uint8Array(result.encryptedState),
      version: result.version,
      baselineSignature: new Uint8Array(result.baselineSignature),
    };
  }

  async getGroupJoinInfo(
    groupId: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> {
    const { groups } = this.requireGroupServerApi();
    const result = await this.convex.query(groups.getGroupJoinInfo, {
      groupId: this.toBytes(groupId),
      inviteLinkPassword: this.toBytes(inviteLinkPassword),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
    if (!result) return null;
    return {
      encryptedJoinInfo: new Uint8Array(result.encryptedJoinInfo),
      version: result.version,
    };
  }

  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangePage> {
    const { groups } = this.requireGroupServerApi();
    const result = await this.convex.query(groups.getGroupChanges, {
      groupId: this.toBytes(groupId),
      fromVersion,
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
    return {
      entries: result.entries.map(
        (entry: {
          version: number;
          actions: ArrayBuffer;
          serverSignature: ArrayBuffer;
          changeEpoch: number;
          timestamp: number;
        }) => ({
          version: entry.version,
          actions: new Uint8Array(entry.actions),
          serverSignature: new Uint8Array(entry.serverSignature),
          changeEpoch: entry.changeEpoch,
          timestamp: entry.timestamp,
        })
      ),
      hasMore: result.hasMore,
    };
  }

  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<GroupChangeEntry> {
    // S13: the server derives the change epoch from the accepted actions; a
    // legacy caller-supplied epoch must be rejected, matching
    // ConvexGroupServer.submitGroupChange.
    if (arguments.length !== 5) {
      throw new Error(
        'INVALID_REQUEST: Group change submission must not carry an epoch'
      );
    }
    const { groups } = this.requireGroupServerApi();
    const result = await this.convex.mutation(groups.submitGroupChange, {
      groupId: this.toBytes(groupId),
      expectedVersion,
      actions: this.toBytes(actions),
      inviteLinkPassword: this.toBytes(inviteLinkPassword),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
    return {
      version: result.version,
      actions: new Uint8Array(result.actions),
      serverSignature: new Uint8Array(result.serverSignature),
      changeEpoch: result.changeEpoch,
      timestamp: result.timestamp,
    };
  }

  async issueAuthCredential(_userId: string): Promise<Uint8Array> {
    // userId kept for ISignalProtocolRelayServer interface compat; server uses auth session
    const api = this.requireGroupServerApi();
    const result = await this.convex.mutation(api.zkAuth.issueAuthCredentialMutation, {});
    return new Uint8Array(result);
  }

  async issueProfileKeyCredential(
    profileKey: Uint8Array
  ): Promise<Uint8Array> {
    const api = this.requireGroupServerApi();
    const result = await this.convex.mutation(
      api.zkAuth.issueProfileKeyCredentialMutation,
      { profileKey: this.toBytes(profileKey) }
    );
    return new Uint8Array(result);
  }

  async refreshGroupSendEndorsements(
    groupId: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ endorsements: Uint8Array; expiration: number }> {
    const api = this.requireGroupServerApi();
    const result = await this.convex.mutation(api.groups.refreshGroupSendEndorsements, {
      groupId: this.toBytes(groupId),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
    return {
      endorsements: new Uint8Array(result.endorsements),
      expiration: result.expiration,
    };
  }

  // ════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ════════════════════════════════════════════════════════════════════════════

  private requireGroupServerApi(): {
    groups: NonNullable<ConvexSignalProtocolRelayApi['groups']>;
    zkAuth: NonNullable<ConvexSignalProtocolRelayApi['zkAuth']>;
  } {
    if (!this.api.groups || !this.api.zkAuth) {
      throw new Error(
        'This Convex relay does not expose the groupServer capability; configure both groups and zkAuth API modules'
      );
    }
    return {
      groups: this.api.groups,
      zkAuth: this.api.zkAuth,
    };
  }

  /** Convert Uint8Array to ArrayBuffer for Convex v.bytes() args. */
  private toBytes(data: Uint8Array): ArrayBuffer {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  }

  private uint8ArrayToBase64(data: Uint8Array): string {
    // Use Buffer in Node.js or btoa in browser
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(data).toString('base64');
    }
    let binary = '';
    const len = data.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
  }

  private base64ToUint8Array(base64: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Clean up all subscriptions and close the internal subscription client.
   */
  async destroy(): Promise<void> {
    // Unsubscribe all active subscriptions
    for (const unsubscribe of this.subscriptions.values()) {
      unsubscribe();
    }
    this.subscriptions.clear();

    // Close the internal subscription client if it exists
    if (this.subscriptionClient) {
      await this.subscriptionClient.close();
      this.subscriptionClient = null;
    }
  }
}
