/**
 * OpenE2EE Signal Protocol SDK - Modern Public API
 *
 * This is the main entry point for the OpenE2EE Signal Protocol SDK's protocol implementation.
 * It follows modern TypeScript/JavaScript SDK patterns with factory-based initialization,
 * namespaced utilities, and clean exports.
 *
 * ## Primary API: createSignalProtocolClient()
 *
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 * import { mockRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/mock';
 * import { mockStore } from '@open-e2ee/signal-protocol-sdk/local/store/mock';
 *
 * const relay = mockRelay();
 * const alice = await createSignalProtocolClient({
 *   identity: { userId: 'alice' },
 *   adapters: { storage: mockStore(), relay },
 * });
 *
 * const bob = await createSignalProtocolClient({
 *   identity: { userId: 'bob' },
 *   adapters: { storage: mockStore(), relay },
 * });
 *
 * await alice.syncToServer();
 * await bob.syncToServer();
 * await alice.send('bob', 'Hello!');
 * ```
 *
 * ## Namespaced Utilities
 *
 * ```typescript
 * import { safety, keys, encoding } from '@open-e2ee/signal-protocol-sdk';
 *
 * const keyPair = await keys.generateIdentityKeyPair();
 * const safetyNum = await signal.verify('bob');
 * await signal.confirmSafetyNumber(safetyNum.confirmation);
 * const b64 = encoding.bytesToBase64(keyPair.publicKey);
 * ```
 *
 * ## Architecture
 *
 * - **SignalProtocolClient**: Primary API (factory pattern, type-safe initialization)
 * - **Namespaces**: Organized utilities (safety, keys, encoding)
 * - **Types**: Comprehensive TypeScript definitions
 * - **Internal Protocol**: SCREAMING_SNAKE_CASE matching Signal Protocol notation
 *
 * See ARCHITECTURE.md for package boundaries and naming conventions.
 */

// ============================================================================
// PRIMARY API: createSignalProtocolClient() and SignalProtocolClient
// ============================================================================

/**
 * Modern Signal Protocol client.
 *
 * Most app code should create this through `createSignalProtocolClient()` so identity,
 * adapters, and security policy are grouped in one object. Use
 * `SignalProtocolClient.create()` directly when lower-level integration code already owns
 * the flattened config shape.
 *
 * @example
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 * });
 * await signal.send('bob', 'Hello!');
 * ```
 */
export {};
export { SignalProtocolClient } from './client';
export {
  BraidPolicy,
  createSignalProtocolClient,
  createSignalProtocolClientConfig,
  PostQuantumPolicy,
} from './client';
export type {
  SignalProtocolClientAdapterConfig,
  SignalProtocolClientCompositionOptions,
  SignalProtocolClientIdentityConfig,
  SignalProtocolConfig,
} from './client';
export type {
  SignalProtocolClientConfig,
  ProgressCallback,
  ILogger,
  DoubleRatchetConfig,
  PreKeyMaintenanceStore,
  ProtocolStrategyConfig,
  SCKAMode,
  SealedSenderConfig,
  SenderKeysConfig,
  // SPQR limits configuration types
  SPQRLimits,
  ResolvedSPQRLimits,
} from './client/config';
export type {
  SignalProtocolClientDeleteLocalAttachmentInput,
  SignalProtocolClientLoadedLocalAttachment,
  SignalProtocolClientLoadLocalAttachmentInput,
  SignalProtocolClientMedia,
  SignalProtocolClientMediaCompletedResult,
  SignalProtocolClientMediaCleanupInput,
  SignalProtocolClientMediaCleanupResult,
  SignalProtocolClientMediaConfig,
  SignalProtocolClientMediaDownloadCompletedResult,
  SignalProtocolClientMediaDownloadInput,
  SignalProtocolClientMediaDownloadNotNeededResult,
  SignalProtocolClientMediaDownloadResult,
  SignalProtocolClientMediaFailedResult,
  SignalProtocolClientMediaOperationOptions,
  SignalProtocolClientMediaOperationResult,
  SignalProtocolClientMediaPendingResult,
  SignalProtocolClientMediaProcessResult,
  SignalProtocolClientMediaSkippedResult,
  SignalProtocolClientMediaUploadCompletedResult,
  SignalProtocolClientMediaUploadInput,
  SignalProtocolClientMediaUploadResult,
  SignalProtocolClientProcessPendingMediaOptions,
  SignalProtocolClientSaveDownloadedAttachmentInput,
  SignalProtocolClientSaveUploadedAttachmentInput,
  SignalProtocolClientSyncDeleteInput,
} from './client';
export {
  SPQR_LIMITS_DEFAULTS,
  resolveSPQRLimits,
  // Key rotation timing constants (profile defaults)
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_PREKEY_AGE_MS_DEFAULT,
} from './client/config';
export type {
  AttachmentTransferOptions,
  DownloadedAttachment,
  PreparedAttachmentUpload,
  SendOptions,
  SendResult,
  SafetyNumber,
  SafetyNumberConfirmation,
  DataMessageInput,
  IncomingEnvelope,
  ProcessEnvelopeOptions,
  SessionHealthResult,
  TypingAction,
} from './client/types';
export type {
  BlockedRecipientsSyncInput,
  InspectedSignalProtocolContent,
  ParsedReceiptContent,
  ParsedTypingContent,
  ConfigurationSyncInput,
  MediaAttachmentDeleteSyncInput,
  ReadSyncEntryInput,
  RecipientUsernameSyncInput,
  SentSyncTranscriptInput,
  TaskNotificationAckSyncInput,
  UsernameStateSyncInput,
  VerificationStateSyncInput,
  ViewOnceOpenSyncInput,
  SignalProtocolContentAdapter,
} from './client/content-adapter';
export type { ForceKeyResetResult, PreKeyStatusResult } from './client/prekeys';
export { EndorsementManager } from './client/endorsement-manager';
export { createDefaultSignalProtocolContentAdapter } from './client/content-adapter';
export {
  SignalProtocolBlockingManager,
  type SignalProtocolBlockingManagerOptions,
  type BlockedRecipientEntry,
  type SignalProtocolBlockingStore,
  type SignalProtocolBlockingMirror,
  type SignalProtocolBlockingHooks,
} from './blocking';

/**
 * Protocol Address for type-safe device addressing
 *
 * ProtocolAddress represents a unique device in the Signal Protocol.
 * Format: userId:deviceId (e.g., "bob:1" for Bob's first device)
 *
 * @example
 * ```typescript
 * import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';
 *
 * const bob = ProtocolAddress.create('bob', 1);
 * const parsed = ProtocolAddress.parse('alice:2');
 * const str = ProtocolAddress.toString(bob); // "bob:1"
 * ```
 */
export { ProtocolAddress } from './types/address';

// ============================================================================
// LOGGER UTILITIES
// ============================================================================

/**
 * Logging utilities for app composition
 *
 * Pass a logger into `createSignalProtocolClient()` to route Signal Protocol logs through
 * your app logger or custom diagnostics pipeline.
 *
 * @example Using custom logger with SignalProtocolClient
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage },
 *   logger: {
 *     info: (msg, data) => myLogger.log('info', msg, data),
 *     error: (msg, err) => myLogger.log('error', msg, err),
 *     warn: (msg, data) => myLogger.log('warn', msg, data)
 *   }
 * });
 * ```
 */
export { createDefaultSignalProtocolLogger, defaultSignalProtocolLogger, resolveSignalProtocolLogger } from './logger';

// ============================================================================
// NAMESPACED UTILITIES
// ============================================================================

// NOTE: crypto is internal-only. For app-owned attachment download/cache flows,
// use the stable `@open-e2ee/signal-protocol-sdk/files` subpath instead of reaching into
// internal crypto modules.

/**
 * Safety number utilities
 *
 * Import directly from sub-path for cleaner imports:
 * ```typescript
 * import { generateCompositeSafetyNumber, compareSafetyNumbers } from '@open-e2ee/signal-protocol-sdk/safety';
 * ```
 *
 * Or use namespace import:
 * ```typescript
 * import { safety } from '@open-e2ee/signal-protocol-sdk';
 * safety.generateCompositeSafetyNumber(...);
 * ```
 */
export * as safety from './safety';

/**
 * Key generation utilities namespace
 *
 * @example
 * ```typescript
 * import { keys } from '@open-e2ee/signal-protocol-sdk';
 * const identityKey = await keys.generateIdentityKeyPair();
 * const signedPreKey = await keys.generateEcSignedPreKey(signingKey);
 * ```
 */
export * as keys from './keys';

/**
 * Encoding utilities namespace (base64, hex, byte conversions)
 *
 * @example
 * ```typescript
 * import { encoding } from '@open-e2ee/signal-protocol-sdk';
 * const b64 = encoding.bytesToBase64(data);
 * const hex = encoding.bytesToHex(data);
 * ```
 */
export * as encoding from './encoding';
export * as blocking from './blocking';
export * as media from './media';
export {
  MediaAttachmentFlag,
  MediaAttachmentJobOperation,
  MediaAttachmentJobPriority,
  MediaAttachmentJobSource,
  MediaAttachmentJobExecutionStatus,
  MediaAttachmentMessageType,
  MediaAttachmentError,
  MediaAttachmentErrorCode,
  createMediaAttachmentMessage,
  createMediaAttachmentDeliveryId,
  createMediaAttachmentId,
  createMediaAttachmentPointer,
  createByteRangeMediaAttachmentTransfer,
  createTusMediaAttachmentTransfer,
  deleteMediaAttachment,
  downloadMediaAttachment,
  executeMediaAttachmentJob,
  MediaAttachmentCleanupReason,
  MEDIA_ATTACHMENT_POLICY_DEFAULTS,
  MEDIA_ATTACHMENT_POLICY_PRESETS,
  parseMediaAttachmentMessage,
  planMediaAttachmentCleanup,
  planMediaAttachmentCleanupJobs,
  planMediaAttachmentDownloadJob,
  planMediaAttachmentDeleteSync,
  planMediaAttachmentOpen,
  planMediaAttachmentProcessing,
  planMediaAttachmentUploadJob,
  prepareMediaAttachmentUpload,
  resolveMediaAttachment,
  serializeMediaAttachmentMessage,
  validateMediaAttachmentPolicy,
} from './media';
export type {
  CreateMediaAttachmentPointerInput,
  DeleteMediaAttachmentOptions,
  DeleteMediaAttachmentResult,
  ByteRangeMediaAttachmentPartialStore,
  ByteRangeMediaAttachmentTransferOptions,
  MediaAttachmentBackgroundJob,
  MediaAttachmentCheckpointCallback,
  MediaAttachmentCleanupPlan,
  MediaAttachmentCleanupReason as MediaAttachmentCleanupReasonValue,
  MediaAttachmentErrorCode as MediaAttachmentErrorCodeValue,
  MediaAttachmentFlag as MediaAttachmentFlagValue,
  MediaAttachmentJobOperation as MediaAttachmentJobOperationValue,
  MediaAttachmentJobPriority as MediaAttachmentJobPriorityValue,
  MediaAttachmentJobSource as MediaAttachmentJobSourceValue,
  MediaAttachmentJobExecutionStatus as MediaAttachmentJobExecutionStatusValue,
  MediaAttachmentJobExecutionResult,
  MediaAttachmentJobSkipReason,
  MediaAttachmentMessage,
  MediaAttachmentMessageType as MediaAttachmentMessageTypeValue,
  MediaAttachmentPointer,
  MediaAttachmentProcessingPlan,
  MediaAttachmentPolicy,
  MediaAttachmentProgress,
  MediaAttachmentProgressCallback,
  MediaAttachmentRetryOptions,
  MediaAttachmentResumeState,
  MediaAttachmentTransfer,
  MediaAttachmentTransferCheckpoint,
  MediaAttachmentTransferOptions,
  MediaAttachmentUploadResponse,
  MediaAttachmentUploadJobData,
  MediaAttachmentKnownIds,
  MediaAttachmentOpenDecision,
  ExecuteMediaAttachmentJobOptions,
  PlanMediaAttachmentCleanupJobsInput,
  PlanMediaAttachmentDeleteSyncInput,
  PlanMediaAttachmentDownloadJobInput,
  PlanMediaAttachmentOpenInput,
  PlanMediaAttachmentProcessingInput,
  PlanMediaAttachmentUploadJobInput,
  PrepareMediaAttachmentUploadOptions,
  ResolveMediaAttachmentOptions,
  ResolvedMediaAttachment,
  TusMediaAttachmentTransferOptions,
} from './media';

// Group ID utilities (Signal Protocol V2 prefix format)
//
// Full GroupsV2 contracts and managers live on `@open-e2ee/signal-protocol-sdk/groups`.
export { GROUP_V2_PREFIX, isGroupId, createGroupId, extractGroupId } from './internal/groups';

export type { GroupId } from './internal/groups';

/**
 * Remote infrastructure interfaces (DI contracts)
 *
 * - **ISignalProtocolRelayServer**: Envelope delivery, device registry, and prekeys
 * - **SignalProtocolRemoteObjectStore**: Brokered remote storage for encrypted objects
 *
 * @see docs/INTERFACES.md for full documentation
 *
 * @example
 * ```typescript
 * import type { ISignalProtocolRelayServer, SignalProtocolRemoteObjectStore } from '@open-e2ee/signal-protocol-sdk';
 * import { convexRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 *
 * const relay: ISignalProtocolRelayServer = convexRelay({ convex, api: signalApi, currentUserId: userId });
 * ```
 */
export type {
  ISignalProtocolRelayServer,
  Envelope,
  DeviceInfo,
  DeviceType,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle as RelayPreKeyBundle, // Alias to avoid conflict with keys/PreKeyBundle
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  EcSignedPreKeyUpload,
  GroupChangeEntry,
  GroupMemberDevice,
  KemLastResortPreKeyUpload,
  SealedSenderAuth,
  Unsubscribe,
} from './remote/relay/types';
export type {
  RemoteObjectCompleteUploadRequest,
  RemoteObjectDeleteRequest,
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from './remote/object-store';

// ============================================================================
// TYPE EXPORTS
// ============================================================================

// Key types - from canonical keys module
export type {
  PublicKey,
  PrivateKey,
  Signature,
  Ciphertext,
  KeyPair,
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  PreKeyBundle,
} from './keys';

// Other types - from types/
export type {
  // Session types
  SessionState,
  SessionRecord,
  SessionRecordMetadata,
  ReceiverChain,
  TripleRatchetState,
  SPQRState,
  SCKAState,
  KDFChain,

  // Address types (ProtocolAddress exported as value above for namespace functions)

  // Message types
  MessageHeader,
  RatchetMessage,
  PreKeyMessage,

  // NOTE: EncryptedFile, FileEncryptionKey, EncryptedPhoto, PhotoEncryptionKey
  // were removed - these are app-domain types that should be defined in the app
  // layer, alongside whatever encryption wrappers the application needs.

  // API types
  ISignalProtocolClient,
  ISignalProtocolManager,
  ISignalProtocolLocalStore,
  ISignalProtocolLocalSecretVault,
  MessageRecord,
  SkippedSenderMessageKey,

  // Focused store interfaces with independently replaceable responsibilities.
  IIdentityKeyStore,
  IEcOneTimePreKeyStore,
  IEcSignedPreKeyStore,
  IKyberLastResortPreKeyStore,
  IKemPreKeyStore,
  ISessionStore,
  ISesameStore,
  ISenderKeyStore,
  IProtocolStore,
  SessionTrustCommit,

  // Error context
  EncryptionErrorContext,

  // Utility types
  Base64,
  Hex,
  Bytes,
} from './types';

// Supporting types referenced by public client, store, relay, and group APIs.
export type {
  DeviceRecord,
  RetryRequest,
  SesameMessage,
  SesameStats,
  UserRecord,
} from './internal/sesame/types';
export type {
  GroupAuthorization,
  IGroupServer,
  IGroupStateStore,
} from './internal/groups-v2/manager';
export type { DecryptedGroup } from './internal/groups-v2/types';
export type { SenderKeyState } from './internal/protocol/sender-keys/manager';
export type {
  MLKEMBraidAgentState,
  MLKEMBraidMessage,
} from './internal/protocol/spqr/ml-kem-braid/types';
export type { ResolvedSPQRInfoStrings } from './internal/crypto/kdf/hkdf';
export type { VersionNegotiationState } from './internal/protocol/version';
export type { ServiceId } from './internal/protocol/zk/groups/uid-struct';
export type { CredentialPublicKey } from './internal/protocol/zk/credentials/credentials';
export { VerificationFailure } from './internal/protocol/zk/credentials/issuance';
export {
  ServerDerivedKeyPair,
  ServerDerivedPublicKey,
  ServerRootKeyPair,
  ServerRootPublicKey,
} from './internal/protocol/zk/credentials/endorsements';

// Event hooks (callbacks for SignalProtocolClient) - from client/
export type { SignalProtocolClientHooks, HookName, DecryptedEnvelope } from './client/event-hooks';

// Error types, message types, and enums
export {
  EncryptionError,
  EncryptionErrorCode,
  MessageType,
  ContentHint,
  IdentityKeyChange,
  TrustDirection,
} from './types';

// Sealed-sender authorization errors
export { SealedSenderAuthError, isSealedSenderAuthError } from './types/errors';

// NOTE: Cryptographic constants moved to internal. Import from './internal/crypto' if needed.

// Protocol constants (device IDs, limits) - co-located with types
export {
  DEFAULT_DEVICE_ID,
  MIN_REGISTRATION_ID,
  MAX_REGISTRATION_ID,
  ONE_TIME_PREKEY_BATCH_SIZE,
} from './types/protocol-constants';

// Protocol limits
export {
  MAX_MESSAGE_KEYS,
  MAX_SKIP,
  MAX_RECEIVER_CHAINS,
} from './internal/protocol/double-ratchet';

// Version constants - spec versions and wire format versions
export {
  // Signal Protocol specification versions
  X3DH_SPEC,
  PQXDH_SPEC,
  DOUBLE_RATCHET_SPEC,
  SENDER_KEY_SPEC,
  SESAME_SPEC,
  ML_KEM_BRAID_SPEC,

  // Wire format versions (our serialization format)
  MESSAGE_FORMAT,
  SESSION_FORMAT,
  SENDER_KEY_FORMAT,

  // Version utilities
  parseVersion,
  isCompatible,
  formatVersion,
} from './versions';

// NOTE: Protocol state types (DoubleRatchetState, SenderKeyState, etc.) moved to internal.
// Internal crypto remains outside the supported public surface.

// Sender-key type re-export for boundary-safe composition
export type { SenderKeyDistributionMessage } from './internal/protocol/sender-keys';
