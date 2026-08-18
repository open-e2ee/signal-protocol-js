/**
 * Configuration types for `SignalProtocolClient`.
 *
 * Adapter, protocol-policy, and lifecycle options remain explicit so
 * applications can compose the client for their own runtime.
 */

import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { ISignalProtocolLocalStore, ISignalProtocolManager } from '../types/api';
import type { IdentityType } from '../keys/types';
import type { ILogger } from '../logger';
import type { SignalProtocolClientHooks } from './event-hooks';
import type { SignalProtocolContentAdapter } from './content-adapter';
import type { SignalProtocolClientMediaConfig } from './media';
import type {
  PreKeyMaintenanceStore,
  ProtocolStrategyConfig,
  SignalProtocolConfig,
  SenderKeysConfig,
} from '../types/protocol-config';
export type { ILogger } from '../logger';
export {};
export type {
  BraidProgressEvent,
  ClassicalFallbackReason,
  NetworkConstraints,
  ProtocolSelectionEvent,
  ProtocolStrategyConfig,
  ProtocolStrategyValidation,
  PreKeyMaintenanceStore,
  ReplacedOneTimePreKeyCullResult,
  ReplacedPreKeyCullResult,
  ResolvedKeyExchangeInfoStrings,
  ResolvedSPQRLimits,
  SCKAMode,
  SenderKeysConfig,
  SignalProtocolConfig,
  SPQRInfoStrings,
  SPQRLimits,
} from '../types/protocol-config';
export {
  applyProtocolStrategyDefaults,
  ARCHIVED_STATES_MAX_LENGTH,
  BraidPolicy,
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_PREKEY_AGE_MS_DEFAULT,
  MAX_SENDER_KEY_STATES,
  MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
  PostQuantumPolicy,
  PQXDH_INFO_DEFAULT,
  PREKEY_CHECK_THROTTLE_MS_DEFAULT,
  protocolConfigToStrategy,
  resolveKeyExchangeInfoStrings,
  resolveSCKAMode,
  resolveSignalProtocolStrategy,
  resolveSPQRLimits,
  SENDER_KEYS_DEFAULTS,
  SPQR_LIMITS_DEFAULTS,
  validateProtocolStrategy,
  X3DH_INFO_DEFAULT,
} from '../types/protocol-config';

/**
 * Sealed Sender access mode.
 *
 * Controls who can send sealed sender messages to this user:
 * - `unrestricted`: Anyone can send sealed sender messages (default)
 * - `contacts-only`: Only contacts who know the profile key can send
 * - `disabled`: Sealed sender is fully disabled
 */
export type SealedSenderAccessMode = 'unrestricted' | 'contacts-only' | 'disabled';

/**
 * Sealed Sender configuration.
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export interface SealedSenderConfig {
  /**
   * Ed25519 trust root public keys for certificate validation.
   *
   * Clients use these to validate the certificate chain:
   * trust_root signs ServerCertificate -> ServerCertificate signs SenderCertificate
   *
   * Multiple roots work for key rotation scenarios.
   */
  trustRoots: Uint8Array[];

  /**
   * Provider function that returns a serialized SenderCertificate (base64).
   *
   * The client calls this lazily when it sends a sealed sender message and the
   * cached certificate expired. The client caches the returned certificate for
   * its validity period (typically 24 hours).
   *
   * @returns Base64-encoded serialized SenderCertificate
   */
  certificateProvider?: () => Promise<string>;

  /**
   * Who may send sealed sender messages to this user.
   *
   * @default 'unrestricted'
   */
  accessMode?: SealedSenderAccessMode;

  /**
   * Optional host-provided contact profile state store.
   *
   * When present, the Signal Protocol client can use per-contact profile keys
   * and unidentified-access mode for direct-message sealed sender sends. It
   * does not import the host app's persistence layer.
   */
  contactStateStore?: import('../profile/contact-state').ContactProfileStateStore;
}

/** Certificate expiration safety margin (5 minutes in milliseconds). */
export const SEALED_SENDER_CERTIFICATE_MARGIN_MS = 5 * 60 * 1000;

/**
 * Signal Protocol configuration options
 */
export interface DoubleRatchetConfig {
  /**
   * Maximum number of messages to skip when receiving out-of-order messages
   * Default: 1000 (Signal Protocol recommendation)
   */
  maxSkip?: number;

  /**
   * Maximum number of skipped message keys to store
   * Default: 1000
   */
  maxMessageKeysStored?: number;

  /**
   * Key expiration time in milliseconds
   * Default: 7 days (604800000 ms)
   */
  keyExpirationMs?: number;
}

/**
 * Low-level SignalProtocolClient configuration options.
 *
 * Application code should usually prefer `createSignalProtocolClient()`, which groups
 * account identity, adapters, and protocol policy into a friendlier shape. Use
 * this config directly when lower-level integration code already flattened
 * client options.
 *
 * @example
 * ```typescript
 * import {
 *   createSignalProtocolClient,
 *   SignalProtocolClient,
 * } from '@open-e2ee/signal-protocol-sdk';
 * import {
 *   convexRelay,
 *   type ConvexSignalProtocolRelayApi,
 * } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
 * const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });
 *
 * // Preferred app-facing composition.
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 * });
 *
 * // Low-level factory with the same underlying options.
 * const advancedSignalProtocol = await SignalProtocolClient.create(userId, {
 *   storage,
 *   relay,
 *   onProgress,
 *   ratchetConfig: {
 *     maxSkip: 2000,
 *     keyExpirationMs: 14 * 24 * 60 * 60 * 1000 // 14 days
 *   },
 *   enableDebugLogging: true
 * });
 * ```
 */
export interface SignalProtocolClientConfig {
  /**
   * Device identifier for multi-device support
   *
   * - 1 = Primary device (default)
   * - 2-5 = Linked devices
   *
   * Device 1 bootstraps identity locally. Devices 2-5 must already have a
   * provisioned identity imported into the provided storage before the app
   * calls `SignalProtocolClient.create()`.
   *
   * Prekeys and sessions remain device-specific. Devices share account identity.
   * Maximum 5 devices per user (1 primary + 4 linked).
   *
   * @default 1 (primary device)
   *
   * @example
   * ```typescript
   * // Primary device
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   deviceId: 1
   * });
   *
   * // Linked device (from QR code provisioning)
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: provisionedLinkedDeviceStorage,
   *   deviceId: 2
   * });
   * ```
   */
  deviceId?: number;

  /**
   * Enable PNI (Phone Number Identity) cryptographic key generation
   *
   * When `true`, generates and syncs both ACI and PNI identity keys, prekeys,
   * and Kyber prekeys for applications that maintain both account identifiers.
   *
   * When `false` (default), the client generates and synchronizes only ACI keys. Use
   * this for applications whose account model does not require PNI keys.
   *
   * This leaves the PNI UUID on the users table alone. It can still exist for ZK
   * group credentials without generating cryptographic keys.
   *
   * @default false
   */
  enablePniKeys?: boolean;

  /**
   * This account's ACI for Group System credential presentation.
   *
   * Required when you configure `groups`.
   */
  aci?: import('../internal/protocol/zk/groups/uid-struct').ServiceId;

  /** This account's optional PNI for Group System credential presentation. */
  pni?: import('../internal/protocol/zk/groups/uid-struct').ServiceId;

  /**
   * Relay adapter for server synchronization.
   *
   * If provided, the client will automatically:
   * 1. Generate prekey bundle
   * 2. Upload public keys to the relay server
   * 3. Provide progress updates via onProgress callback
   *
   * If omitted, client operates in local-only mode.
   *
   * @example
   * ```typescript
   * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
   * import {
   *   convexRelay,
   *   type ConvexSignalProtocolRelayApi,
   * } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
   * import { api } from '../convex/_generated/api';
   *
   * const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
   * const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });
   *
   * const signal = await createSignalProtocolClient({
   *   identity: { userId },
   *   adapters: { storage, relay },
   * });
   * ```
   */
  relay?: ISignalProtocolRelayServer;

  /**
   * Remote object store adapter for encrypted file uploads (two-layer encryption)
   *
   * If provided, enables encrypted file upload (two-layer encryption):
   * 1. Generate AES-256-GCM key
   * 2. Encrypt file bytes with AES
   * 3. Upload encrypted bytes to object storage
   * 4. Send storage ID + key via Signal Protocol
   *
   * If omitted, file upload operations will throw an error.
   *
   * @example
   * ```typescript
   * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
   * import { convexR2ObjectStore } from '@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2';
   * import { api } from '../convex/_generated/api';
   *
   * const remoteObjectStore = convexR2ObjectStore({
   *   convex,
   *   api: api.signalObjectStore,
   * });
   *
   * const signal = await createSignalProtocolClient({
   *   identity: { userId },
   *   adapters: { storage, relay, remoteObjectStore },
   * });
   *
   * // Send file bytes
   * const fileBytes = new Uint8Array(await file.arrayBuffer());
   * await signal.send('bob', fileBytes, { mimeType: 'image/jpeg' });
   * ```
   */
  remoteObjectStore?: SignalProtocolRemoteObjectStore;

  /**
   * App-owned media lifecycle callbacks for the SignalProtocolClient media queue.
   *
   * The existing Signal Protocol local storage adapter persists the queue
   * itself. These callbacks keep local bytes, plaintext caches, and product
   * state in the app layer. There they can share file permissions, UI state,
   * and app database ownership.
   *
   * @example
   * ```typescript
   * const signal = await createSignalProtocolClient({
   *   identity: { userId },
   *   adapters: { storage, relay, remoteObjectStore },
   *   media: {
   *     loadLocalAttachment: async ({ localMediaId }) => appDrafts.readBytes(localMediaId),
   *     saveUploadedAttachment: async ({ localMediaId, attachment }) =>
   *       appPointers.save(localMediaId, attachment),
   *     saveDownloadedAttachment: async ({ attachmentId, downloaded }) =>
   *       appMediaCache.save(attachmentId, downloaded.data),
   *     deleteLocalAttachment: async ({ attachmentId }) => appMediaCache.delete(attachmentId),
   *   },
   * });
   * ```
   */
  media?: SignalProtocolClientMediaConfig;

  /**
   * Progress callback for initialization and relay sync operations.
   *
   * Receives updates during:
   * - Key generation
   * - Prekey bundle generation
   * - Relay upload
   *
   * @example
   * ```typescript
   * const signal = await createSignalProtocolClient({
   *   identity: { userId },
   *   adapters: { storage, relay },
   *   onProgress: ({ stage, percent, message }) => {
   *     console.log(`${stage}: ${percent}% - ${message}`);
   *   }
   * });
   * ```
   */
  onProgress?: ProgressCallback;

  /**
   * Local store implementation for the current runtime.
   * Required by SignalProtocolClient.create().
   */
  storage: ISignalProtocolLocalStore;

  /**
   * Signal Protocol Manager implementation (for advanced use cases)
   * Default: Creates new SignalProtocolManager instance
   */
  protocolManager?: ISignalProtocolManager;

  /**
   * Double Ratchet algorithm configuration
   */
  ratchetConfig?: DoubleRatchetConfig;

  /**
   * Developer-facing protocol policy.
   *
   * The default is strict post-quantum behavior with the specification-defined
   * ML-KEM Braid SPQR mode. Use `compatible` only when the product deliberately
   * supports genuinely non-PQ peers. Use `braid: 'disabled'` only when a
   * product-reviewed constraint requires the local direct SPQR mode.
   *
   * @default { postQuantum: 'required', braid: 'required' }
   *
   * @example Strict post-quantum mode
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   protocol: {
   *     postQuantum: 'required',
   *     braid: 'required'
   *   }
   * });
   * ```
   *
   * @example Compatibility with non-PQ peers
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   protocol: {
   *     postQuantum: 'compatible',
   *     braid: 'required'
   *   }
   * });
   * ```
   *
   * @example Explicit direct SPQR mode
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   protocol: {
   *     postQuantum: 'required',
   *     braid: 'disabled'
   *   }
   * });
   * ```
   */
  protocol?: SignalProtocolConfig;

  /**
   * Advanced protocol strategy configuration.
   *
   * Most application code should use `protocol.postQuantum` instead. This seam
   * exists for diagnostics, telemetry callbacks, and advanced tuning.
   *
   * @example Track protocol usage
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   protocolStrategy: {
   *     onProtocolSelected: (event) => {
   *       analytics.track('Protocol Selected', {
   *         pq: event.usedPQXDH,
   *         tripleRatchet: event.usedTripleRatchet,
   *         compatibilityFallback: event.usedClassicalFallback,
   *         fallbackReason: event.classicalFallbackReason
   *       });
   *     }
   *   }
   * });
   * ```
   *
   * @example Show ML-KEM Braid key-agreement progress
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   protocolStrategy: {
   *     onBraidProgress: (event) => {
   *       ratchetIndicator.update({
   *         carried: event.chunksCarried,
   *         required: event.chunksRequired,
   *         epoch: event.epoch
   *       });
   *     }
   *   }
   * });
   * ```
   */
  protocolStrategy?: ProtocolStrategyConfig;

  /**
   * Sender Keys (group messaging) configuration.
   *
   * Controls HKDF info strings, DoS protection limits, and out-of-order
   * message handling for group encryption.
   *
   * @example Custom protocol branding
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   senderKeys: {
   *     hkdfInfoString: 'MyApp Group V1'
   *   }
   * });
   * ```
   *
   * @example Production-recommended limits (these are the defaults)
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   senderKeys: {
   *     maxChainAdvance: 2000,      // DoS protection
   *     maxSkippedKeys: 2000        // Memory limit
   *   }
   * });
   * ```
   */
  senderKeys?: SenderKeysConfig;

  /**
   * Custom logger implementation
   *
   * Default: Environment-aware console logging
   * - Development: verbose (debug, info, warn, error, breadcrumb)
   * - Production: minimal (warn, error only)
   *
   * @example Using custom logger
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   logger: {
   *     info: (msg, data) => myLogger.log('info', msg, data),
   *     error: (msg, err) => myLogger.log('error', msg, err),
   *     warn: (msg, data) => myLogger.log('warn', msg, data)
   *   }
   * });
   * ```
   *
   * @example Using console directly
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   logger: console // Works directly!
   * });
   * ```
   *
   * @example Using pino
   * ```typescript
   * import pino from 'pino';
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   logger: pino({ level: 'info' })
   * });
   * ```
   *
   * @example Silent mode
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   logger: {} // All methods optional
   * });
   * ```
   */
  logger?: ILogger;

  /**
   * Enable debug logging
   * Default: false
   * Recommended: Enable in development, disable in production
   */
  enableDebugLogging?: boolean;

  /**
   * Event hooks for Signal Protocol lifecycle events
   *
   * Provides integration points for applications to react to:
   * - Session establishment/deletion
   * - Key rotation
   * - Message encryption/decryption
   * - Errors and cleanup operations
   *
   * All hooks are optional and support both sync and async implementations.
   * Hook errors are caught internally and will not affect core functionality.
   *
   * Common use cases:
   * - Cache invalidation (ContentManager, React Query)
   * - Analytics and monitoring (Sentry, DataDog)
   * - State management integration (Redux, Zustand)
   * - User notifications
   *
   * @example Basic usage
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   hooks: {
   *     onSessionEstablished: (sessionId) => {
   *       ContentManager.invalidateSession(sessionId);
   *     },
   *     onKeyRotated: (keyType) => {
   *       analytics.track('Key Rotated', { keyType });
   *     }
   *   }
   * });
   * ```
   *
   * @example Error tracking
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   hooks: {
   *     onDecryptionError: (sessionId, error) => {
   *       Sentry.captureException(error, {
   *         tags: { sessionId }
   *       });
   *     }
   *   }
   * });
   * ```
   */
  hooks?: SignalProtocolClientHooks;

  /**
   * Application-provided content adapter.
   *
   * This is the boundary between the protocol layer and app-specific content,
   * notification batching, and privacy preference policy.
   */
  contentAdapter?: SignalProtocolContentAdapter;

  /**
   * Throw detailed errors instead of generic messages
   * Default: false (generic error messages for security)
   * Recommended: Enable in development for debugging
   */
  throwDetailedErrors?: boolean;

  /**
   * Callback for the moment one-time prekeys run low
   *
   * Called when prekey count drops below the threshold (default: 50).
   * Use this to trigger prekey replenishment to prevent session
   * establishment failures.
   *
   * @example
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   onPreKeyLow: (remaining) => {
   *     console.warn(`Only ${remaining} prekeys remaining, replenishment needed`);
   *     // Trigger server-side prekey generation
   *     backend.replenishPrekeys(userId);
   *   }
   * });
   * ```
   */
  onPreKeyLow?: (remaining: number) => void;

  /**
   * Threshold for prekey low warning
   * Default: 50 (warn when fewer than 50 one-time prekeys remain)
   */
  preKeyLowThreshold?: number;

  /**
   * Key refresh interval in milliseconds.
   *
   * Controls how often the client rotates signed prekeys and Kyber (last-resort) prekeys.
   * Per PQXDH specification Section 3.2, both key types use the same rotation
   * schedule for synchronized post-quantum security.
   *
   * @default 172800000 (2 days)
   *
   * @example Default rotation interval
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   keyRefreshIntervalMs: 2 * 24 * 60 * 60 * 1000 // 2 days
   * });
   * ```
   *
   * @example Weekly rotation (lower bandwidth)
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   keyRefreshIntervalMs: 7 * 24 * 60 * 60 * 1000 // 7 days
   * });
   * ```
   *
   * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
   */
  keyRefreshIntervalMs?: number;

  /**
   * Maximum allowed prekey age in milliseconds.
   *
   * If prekeys exceed this age, the app should block message sending to force
   * key rotation. Provides a safety buffer above keyRefreshIntervalMs.
   *
   * With the default two-day refresh interval, the default maximum age leaves
   * a twelve-day recovery window.
   *
   * @default 1209600000 (14 days)
   *
   * @example Default maximum age
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   maxPreKeyAgeMs: 14 * 24 * 60 * 60 * 1000 // 14 days
   * });
   * ```
   *
   * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
   */
  maxPreKeyAgeMs?: number;

  /**
   * Prekey check throttle interval in milliseconds.
   *
   * Controls how often the client checks the prekey count on app activation.
   * Prevents unnecessary server queries when the app is repeatedly foregrounded.
   *
   * @default 43200000 (12 hours)
   *
   * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
   */
  preKeyCheckThrottleMs?: number;

  /**
   * App-provided prekey bookkeeping store.
   *
   * Needed for SQLite-backed adapters that track replaced prekeys separately
   * from the protocol-facing local store interface.
   */
  preKeyMaintenance?: PreKeyMaintenanceStore;

  /**
   * Runs after the client rotates a group sender key.
   *
   * Useful for logging, analytics, or triggering UI updates when
   * the client rotates sender keys after membership changes.
   *
   * @param groupId - The group whose sender key changed
   * @param newGeneration - The new generation number of the sender key
   *
   * @example
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   onGroupSenderKeyRotated: (groupId, newGeneration) => {
   *     console.log(`Group ${groupId} sender key rotated to gen ${newGeneration}`);
   *     analytics.track('sender_key_rotated', { groupId, newGeneration });
   *   }
   * });
   * ```
   */
  onGroupSenderKeyRotated?: (groupId: string, newGeneration: number) => void;

  /**
   * Sealed Sender configuration for anonymous message delivery.
   *
   * When configured, the client wraps messages in sealed sender encryption
   * that hides the sender's identity from the server. The recipient can
   * still verify the sender via the embedded certificate.
   *
   * Requires:
   * - A relay deployment secret (`OE_GROUPS_SERVER_SECRET`), from which the
   *   relay derives the certificate signing keys. There is no separate signing-key
   *   variable.
   * - The deployment's Ed25519 sender-certificate root public key pinned in
   *   `trustRoots` at build time. Print it with `npx oe-groups trust-root`,
   *   which reports it as `sealed sender trust root` alongside the group trust
   *   root. Never fetch it from a relay at runtime. A relay that can choose
   *   the root that validates it can mint certificates for any sender.
   *
   * With `trustRoots` empty, inbound sealed-sender validation stays disabled
   * and sends fall back to identified delivery, which deanonymizes the sender
   * to the relay.
   *
   * @see https://signal.org/blog/sealed-sender/
   *
   * @example
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   sealedSender: {
   *     trustRoots: [trustRootPublicKeyBytes],
   *     certificateProvider: async () => {
   *       return await convex.mutation(api.signal.certificates.issueSenderCertificate, { deviceId: 1 });
   *     },
   *     accessMode: 'unrestricted',
   *   }
   * });
   * ```
   */
  sealedSender?: SealedSenderConfig;

  /**
   * Group System configuration.
   * Required for group state management (create, sync, membership changes).
   *
   * @example
   * ```typescript
   * const signal = await SignalProtocolClient.create(userId, {
   *   storage: customStorage,
   *   relay,
   *   aci,
   *   pni,
   *   groups: {
   *     trustRoot: GROUP_TRUST_ROOT,
   *     profileKey,
   *   }
   * });
   * ```
   */
  groups?: {
    /**
     * Versioned serialized trust root pinned by the application at build time.
     *
     * This value is never fetched from the relay and trusted at runtime.
     */
    trustRoot: Uint8Array;
    /** This account's 32-byte profile key. */
    profileKey: Uint8Array;
    /** Override the SDK local storage adapter for group state. */
    store?: import('../internal/groups/manager').IGroupStateStore;
    /** Override `relay.groupServer.server` for a custom deployment. */
    server?: import('../internal/groups/manager').IGroupServer;
    /** Override the relay's auth-credential issuance transport. */
    issueCredential?: () => Promise<Uint8Array>;
    /** Override the relay's profile-key credential issuance transport. */
    issueProfileKeyCredential?: () => Promise<Uint8Array>;
    /**
     * Explicitly accept group history without server signatures.
     *
     * This selects the documented non-conforming deployment mode and emits a
     * visible configuration warning.
     */
    allowUnauthenticatedGroupHistory?: boolean;
    /** Receive the §12.3 non-conforming deployment warning. */
    onConfigurationWarning?: (
      warning: import('../internal/groups/manager').GroupConfigurationWarning
    ) => void;
    /** Pre-constructed EndorsementManager for group send endorsement-based auth. */
    endorsementManager?: import('./endorsement-manager').EndorsementManager;
    /** Resolve member ACIs without importing app content models into the client. */
    resolveAciBytesByUserIds?: (userIds: string[]) => Promise<Map<string, Uint8Array>>;
  };
}

/**
 * Get the identity types to operate on based on config.
 *
 * Returns `['aci']` by default, or `['aci', 'pni']` when the application
 * explicitly enables PNI keys.
 */
export function getActiveIdentityTypes(config?: {
  enablePniKeys?: boolean;
}): readonly IdentityType[] {
  return config?.enablePniKeys === true ? (['aci', 'pni'] as const) : (['aci'] as const);
}

/**
 * Progress callback for initialization operations
 */
export type ProgressCallback = (progress: {
  stage: 'generating-keys' | 'generating-kyber' | 'uploading' | 'complete';
  percent: number;
  message: string;
  /** Optional sub-stage progress for granular UI (e.g., "32 of 100 keys") */
  detail?: { current: number; total: number };
}) => void;
