/**
 * Signal Protocol client module.
 *
 * This module exposes the app-facing composition helper and the low-level
 * SignalProtocolClient class for encrypted messaging.
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
export { SignalProtocolClient } from './client';
export {
  createSignalProtocolClient,
  createSignalProtocolClientConfig,
  type SignalProtocolClientAdapterConfig,
  type SignalProtocolClientCompositionOptions,
  type SignalProtocolClientIdentityConfig,
} from './compose';
export { BraidPolicy, PostQuantumPolicy } from './config';
export type { SignalProtocolConfig, SignalProtocolClientConfig } from './config';
export type {
  AttachmentTransferOptions,
  SignalProtocolClientContext,
  DataMessageInput,
  DownloadedAttachment,
  PreparedAttachmentUpload,
  SendOptions,
  SendResult,
  SafetyNumber,
  SafetyNumberConfirmation,
} from './types';
export type {
  BlockedRecipientsSyncInput,
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
} from './content-adapter';
export { createDefaultSignalProtocolContentAdapter } from './content-adapter';
export type { DecryptedEnvelope, SignalProtocolClientHooks } from './event-hooks';
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
} from './media';

// Re-export ProtocolAddress for type-safe API usage
export { ProtocolAddress } from '../types/address';
export type { ProtocolAddress as ProtocolAddressType } from '../types/address';

// Group messaging types (Sender Keys)
export type { SenderKeyDistributionMessage } from '../internal/protocol/sender-keys';
