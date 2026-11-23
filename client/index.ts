/**
 * Signal Protocol client module.
 *
 * This module exposes the app-facing composition helper and the low-level
 * DefaultSignalProtocolClient class for encrypted messaging.
 *
 * @example
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk/client';
 * import { inMemoryStore } from '@open-e2ee/signal-protocol-sdk/local/store/memory';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId: 'alice' },
 *   adapters: { storage: inMemoryStore() },
 * });
 *
 * await signal.send('bob', 'Hello!');
 * ```
 */
export {};
export { DefaultSignalProtocolClient } from "./client";
export {
  createSignalProtocolClient,
  createSignalProtocolClientConfig,
  type SignalProtocolClientAdapterConfig,
  type SignalProtocolClientCompositionOptions,
  type SignalProtocolClientIdentityConfig,
} from "./compose";
export {
  HostedSignalProtocolRelayDeviceLinkError,
  HostedSignalProtocolRelayDeviceRevokedError,
  HostedSignalProtocolRelayDeviceUnknownError,
  HostedSignalProtocolRelayHttpError,
  HostedSignalProtocolRelayPresenceError,
  HostedSignalProtocolRelayUpgradeRequiredError,
  advanceHostedSignalProtocolRelayIdentityMigration,
  createHostedSignalProtocolClient,
  hostedSignalProtocolRelayDeviceOwnedIdentity,
  hostedSignalProtocolRelayPresence,
  hostedSignalProtocolRelaySandboxIdentity,
  hostedSignalProtocolRelayWakePresence,
  linkHostedSignalProtocolRelayDevice,
  pullHostedSignalProtocolRelayAfterWake,
  registerHostedSignalProtocolRelayPush,
  removeHostedSignalProtocolRelayPush,
  type GetIdentityAssertion,
  type HostedSignalProtocolRelayBootstrapAdapter,
  type HostedSignalProtocolRelayBootstrapRequest,
  type HostedSignalProtocolRelayBootstrapResult,
  type HostedSignalProtocolRelayDeviceAuthentication,
  type HostedSignalProtocolRelayIdentityMigrationAction,
  type HostedSignalProtocolRelayIdentityMigrationAdapter,
  type HostedSignalProtocolRelayIdentityMigrationOptions,
  type HostedSignalProtocolRelayIdentityMigrationRequest,
  type HostedSignalProtocolRelayIdentityMigrationSnapshot,
  type HostedSignalProtocolRelayIdentityMigrationState,
  type HostedSignalProtocolRelayIdentityProgress,
  type HostedSignalProtocolRelayIdentityProgressCallback,
  type HostedSignalProtocolRelayManagedDeviceLinkAdapter,
  type HostedSignalProtocolRelayManagedDeviceLinkOptions,
  type HostedSignalProtocolRelayManagedDeviceLinkRequest,
  type HostedSignalProtocolRelayManagedDeviceLinkResult,
  type HostedSignalProtocolRelayPresence,
  type HostedSignalProtocolRelayPresenceAccount,
  type HostedSignalProtocolRelayPresenceApproximateLastSeen,
  type HostedSignalProtocolRelayPresenceAudience,
  type HostedSignalProtocolRelayPresenceErrorCode,
  type HostedSignalProtocolRelayPresenceLastSeenPolicy,
  type HostedSignalProtocolRelayPresenceMode,
  type HostedSignalProtocolRelayPresencePolicy,
  type HostedSignalProtocolRelayPresenceSetting,
  type HostedSignalProtocolRelayPresenceStatus,
  type HostedSignalProtocolRelayPresenceVisibility,
  type HostedSignalProtocolRelayProfileKeys,
  type HostedSignalProtocolRelayPushPlatform,
  type HostedSignalProtocolRelayPushProfile,
  type HostedSignalProtocolRelayPushRegistration,
  type HostedSignalProtocolRelayRegistrationPreKey,
  type HostedSignalProtocolRelayRegistrationPreKeys,
  type HostedSignalProtocolRelayTokenPushRegistration,
  type HostedSignalProtocolRelayWakeClient,
  type HostedSignalProtocolRelayWakeOptions,
  type HostedSignalProtocolRelayWakePresence,
  type HostedSignalProtocolRelayWakeResult,
  type HostedSignalProtocolRelayWebPushRegistration,
  type HostedSignalProtocolClientOptions,
  type IdentityAssertionAssurance,
  type IdentityAssertionProviderRole,
  type IdentityAssertionPurpose,
  type IdentityAssertionRequest,
} from "./hosted";
export {
  joinHostedSignalProtocolRelayAccount,
  type HostedSignalProtocolRelayJoinOptions,
  type HostedSignalProtocolRelayJoinResult,
} from "./hosted-device-join";
export {
  approveHostedSignalProtocolRelayDeviceLink,
  listHostedSignalProtocolRelayDevices,
  removeHostedSignalProtocolRelayDevice,
  renameHostedSignalProtocolRelayDevice,
  type HostedSignalProtocolRelayDeviceLinkApprovalOptions,
  type HostedSignalProtocolRelayOwnDevice,
  type HostedSignalProtocolRelayOwnDevicesChangedCallback,
} from "./hosted-device-management";
export {
  sendHostedSignalProtocolRelayFirstSync,
  type HostedSignalProtocolRelayFirstSyncBundle,
  type HostedSignalProtocolRelayFirstSyncCallback,
  type HostedSignalProtocolRelayFirstSyncContact,
  type HostedSignalProtocolRelayFirstSyncOptions,
} from "./hosted-device-first-sync";
export {
  resetRemovedHostedSignalProtocolRelayDevice,
  type HostedSignalProtocolRelayDeviceResetOptions,
} from "./hosted-device-reset";
export { HostedSignalProtocolRelayDeviceLinkRequiredError } from "./hosted-device-link-required-error";
export {
  HostedSignalProtocolRelayDeviceProvisioningError,
  type HostedSignalProtocolRelayDeviceProvisioningErrorCode,
} from "./hosted-device-provisioning-error";
export {
  bindSignalProtocolRelayLifecycle,
  type SignalProtocolRelayLifecycleAppState,
  type SignalProtocolRelayLifecycleOptions,
} from "./signal-relay-lifecycle";
export { BraidPolicy, PostQuantumPolicy } from "./config";
export type {
  ContentRecoveryDisabledReason,
  ContentRecoveryMode,
  ContentRecoveryPolicy,
  ContentRecoveryStatus,
  GroupMembershipSource,
  HostedSealedSenderConfig,
  ReceiveQueuePolicy,
  SealedSenderConfig,
  SelfHostedSealedSenderConfig,
  SignalProtocolConfig,
  SignalProtocolClientConfig,
  StorageProtectionLevel,
} from "./config";
export type {
  AttachmentTransferOptions,
  SignalProtocolClientContext,
  DataMessageInput,
  DownloadedAttachment,
  OutgoingMessageError,
  PreparedAttachmentUpload,
  SendOptions,
  SendResult,
  SafetyNumber,
  SafetyNumberConfirmation,
} from "./types";
export { isOutgoingMessageError } from "./types";
export {
  DeviceSetReconciliationError,
  SignalProtocolRelayProtocolError,
  type DeviceSetDevice,
  type DeviceSetLastRefusal,
  type DeviceSetPhase,
  type DeviceSetRefusalAccount,
  type DeviceSetUnresolved,
  type DeviceSetUnresolvedReason,
  type SignalProtocolRelayProtocolErrorCode,
  type SignalProtocolRelayProtocolRoute,
} from "./device-set-reconciliation";
export {
  GroupReceiveRefusedError,
  type GroupReceiveDenial,
  GroupReceiveUnavailableError,
  type GroupReceiveUnavailability,
  GroupResendDeferredError,
} from "./group-receive-authorization";
export type {
  BlockedRecipientsSyncInput,
  FirstSyncInput,
  GroupContentContext,
  GroupKeySyncInput,
  InspectedSignalProtocolContent,
  MediaAttachmentDeleteSyncInput,
  ParsedReceiptContent,
  ParsedTypingContent,
  ParsedSyncContent,
  ConfigurationSyncInput,
  ReadSyncEntryInput,
  RecipientUsernameSyncInput,
  SentSyncTranscriptInput,
  TaskNotificationAckSyncInput,
  UsernameStateSyncInput,
  VerificationStateSyncInput,
  ViewOnceOpenSyncInput,
  SignalProtocolContentAdapter,
} from "./content-adapter";
export { createDefaultSignalProtocolContentAdapter } from "./content-adapter";
export type {
  DecryptedEnvelope,
  DeliveredEvent,
  DeliveryErrorCause,
  DeliveryErrorEvent,
  DeliveryRecoveredEvent,
  DeliverySource,
  ReceiveExpiredEvent,
  RetryTerminalClass,
  RetryTerminalEvent,
  RetryTerminalRecoveryEvent,
  SendOutcomeEvent,
  SignalProtocolClientHooks,
} from "./event-hooks";
export type { GroupInitStatus } from "./group-init-status";
export type { IdentityChangedEvent } from "./identity-change";
export type { KeyTransparencyFailureEvent } from "./key-transparency/event";
export type {
  KeyTransparencyCheckOutcome,
  KeyTransparencyUnavailableReason,
} from "./key-transparency/verified-search";
export {
  KeyTransparencyVerificationError,
  type KeyTransparencyFailureCode,
} from "../internal/protocol/key-transparency/errors";
export type {
  SignalProtocolClientDeleteLocalAttachmentInput,
  SignalProtocolClientLoadedLocalAttachment,
  SignalProtocolClientLoadLocalAttachmentInput,
  SignalProtocolClientMedia,
  SignalProtocolClientMediaAbandonmentResult,
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
} from "./media";

// Re-export ProtocolAddress for type-safe API usage
export { ProtocolAddress } from "../types/address";
export type { ProtocolAddress as ProtocolAddressType } from "../types/address";

// Group messaging types (Sender Keys)
export type { SenderKeyDistributionMessage } from "../internal/protocol/sender-keys";

export { resumeHostedSignalProtocolClient, type HostedSignalProtocolResumeOptions } from './hosted-resume';
export { HostedSignalProtocolRelayResumeError, type HostedSignalProtocolRelayResumeErrorCode, type HostedSignalProtocolRelayResumePhase,
  type HostedSignalProtocolRelayResumeProgress,
  type HostedSignalProtocolRelayResumeProgressCallback } from './hosted-resume-error';

export {
  deleteHostedSignalProtocolRelayAccount,
  readHostedSignalProtocolRelayAccountDeletion,
  HostedSignalProtocolRelayAccountDeletionError,
  type HostedSignalProtocolRelayAccountDeletionOptions,
  type HostedSignalProtocolRelayAccountDeletionReceipt,
  type HostedSignalProtocolRelayAccountDeletionErrorCode,
} from './hosted-account-deletion';
