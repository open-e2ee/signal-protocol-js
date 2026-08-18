/**
 * Encrypted-media message contracts.
 *
 * The package sends media as a two-layer encrypted attachment. Encrypted bytes
 * live in a remote object store. The pointer, key, and integrity metadata
 * travel inside an end-to-end encrypted application message.
 */

import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
  constantTimeEqual,
  generateRandomBytes,
  secureZeroBytes,
  sha256,
  streamingDecrypt,
  streamingEncrypt,
} from '../internal/crypto';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import { toBase64 } from '../types/utils';

export {};

export const MediaAttachmentMessageType = {
  Attachment: 'attachment',
} as const;

export type MediaAttachmentMessageType =
  (typeof MediaAttachmentMessageType)[keyof typeof MediaAttachmentMessageType];

export const MediaAttachmentFlag = {
  VoiceMessage: 1,
  Borderless: 2,
  Gif: 8,
} as const;

export type MediaAttachmentFlag = (typeof MediaAttachmentFlag)[keyof typeof MediaAttachmentFlag];

const MEDIA_ATTACHMENT_KEY_BYTES = 32;
const MEDIA_ATTACHMENT_DIGEST_BYTES = 32;
const KNOWN_MEDIA_ATTACHMENT_FLAG_VALUES = new Set<number>([
  0,
  MediaAttachmentFlag.VoiceMessage,
  MediaAttachmentFlag.Borderless,
  MediaAttachmentFlag.Gif,
  MediaAttachmentFlag.VoiceMessage + MediaAttachmentFlag.Borderless,
  MediaAttachmentFlag.VoiceMessage + MediaAttachmentFlag.Gif,
  MediaAttachmentFlag.Borderless + MediaAttachmentFlag.Gif,
  MediaAttachmentFlag.VoiceMessage + MediaAttachmentFlag.Borderless + MediaAttachmentFlag.Gif,
]);
const UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function isMediaAttachmentFlagSet(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    KNOWN_MEDIA_ATTACHMENT_FLAG_VALUES.has(value)
  );
}

function hexByte(value: number): string {
  return value.toString(16).padStart(2, '0');
}

async function generateMediaAttachmentClientUuid(): Promise<string> {
  const bytes = await generateRandomBytes(16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  const hex = Array.from(bytes, hexByte).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20
  )}-${hex.slice(20)}`;
}

/** @internal */
export async function generateMediaAttachmentUploadRequestId(): Promise<string> {
  const bytes = await generateRandomBytes(18);
  return `media-upload/${bytesToUrlSafeBase64(bytes)}`;
}

export interface MediaAttachmentPointer {
  version: 1;
  storageId: string;
  key: string;
  digest: string;
  segmentSize: number;
  ciphertextSize: number;
  contentType: string;
  size: number;
  uploadTimestamp: number;
  clientUuid?: string;
  cdnNumber?: number;
  blurHash?: string;
  thumbnail?: string;
  width?: number;
  height?: number;
  durationMs?: number;
  waveform?: number[];
  fileName?: string;
  caption?: string;
  isViewOnce?: boolean;
  flags?: number;
}

export interface MediaAttachmentMessage {
  type: typeof MediaAttachmentMessageType.Attachment;
  version: 1;
  timestamp: number;
  attachment: MediaAttachmentPointer;
}

export type CreateMediaAttachmentPointerInput = Omit<MediaAttachmentPointer, 'version'> & {
  version?: 1;
};

export const MediaAttachmentErrorCode = {
  RemoteObjectStoreNotConfigured: 'remote-object-store-not-configured',
  UploadFailed: 'upload-failed',
  UploadIdentityChanged: 'upload-identity-changed',
  DownloadFailed: 'download-failed',
  Cancelled: 'cancelled',
  DeleteUnavailable: 'delete-unavailable',
  DeleteFailed: 'delete-failed',
  BlobNotFound: 'blob-not-found',
  ResumeStateInvalid: 'resume-state-invalid',
  JobHandlerMissing: 'job-handler-missing',
  PolicyViolation: 'policy-violation',
  InvalidPointer: 'invalid-pointer',
  CiphertextSizeMismatch: 'ciphertext-size-mismatch',
  DigestMismatch: 'digest-mismatch',
  DecryptionFailed: 'decryption-failed',
  PlaintextSizeMismatch: 'plaintext-size-mismatch',
} as const;

export type MediaAttachmentErrorCode =
  (typeof MediaAttachmentErrorCode)[keyof typeof MediaAttachmentErrorCode];

export class MediaAttachmentError extends Error {
  readonly code: MediaAttachmentErrorCode;
  readonly status?: number;

  constructor(
    message: string,
    code: MediaAttachmentErrorCode,
    options?: { cause?: unknown; status?: number }
  ) {
    super(message);
    this.name = 'MediaAttachmentError';
    this.code = code;
    this.status = options?.status;
    if (options && 'cause' in options) {
      this.cause = options.cause;
    }
  }
}

export interface MediaAttachmentUploadResponse {
  ok: boolean;
  status: number;
  statusText: string;
}

export interface MediaAttachmentProgress {
  operation: 'upload' | 'download' | 'delete';
  phase:
    'encrypt' | 'request-url' | 'transfer' | 'retry' | 'verify' | 'decrypt' | 'complete' | 'delete';
  attempt?: number;
  /** Stable idempotency key for one logical upload. */
  requestId?: string;
  storageId?: string;
  bytesTransferred?: number;
  totalBytes?: number;
  status?: number;
  retryInMs?: number;
  reason?: 'expired-url' | 'invalid-resume' | 'retryable-status' | 'transient-failure';
}

export type MediaAttachmentProgressCallback = (progress: MediaAttachmentProgress) => void;

export interface MediaAttachmentResumeState {
  operation: 'upload' | 'download';
  offsetBytes?: number;
  resumeToken?: string;
  updatedAt: number;
  expiresAt?: number;
}

export interface MediaAttachmentTransferCheckpoint {
  operation: 'upload' | 'download';
  phase: 'request-url' | 'transfer' | 'retry' | 'complete';
  attempt?: number;
  /** Stable idempotency key for one logical upload. */
  requestId?: string;
  storageId?: string;
  attachmentId?: string;
  bytesTransferred?: number;
  totalBytes?: number;
  resumeToken?: string;
  updatedAt: number;
}

export type MediaAttachmentCheckpointCallback = (
  checkpoint: MediaAttachmentTransferCheckpoint
) => void;

export interface MediaAttachmentTransferOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
  attempt?: number;
  totalBytes?: number;
  requestId?: string;
  storageId?: string;
  attachmentId?: string;
}

export interface MediaAttachmentTransfer {
  upload?(
    url: string,
    data: Uint8Array,
    options?: MediaAttachmentTransferOptions
  ): Promise<MediaAttachmentUploadResponse>;
  download?(url: string, options?: MediaAttachmentTransferOptions): Promise<Uint8Array>;
}

export interface TusMediaAttachmentTransferOptions {
  fetch?: typeof fetch;
  chunkSizeBytes?: number;
  tusVersion?: string;
}

export interface ByteRangeMediaAttachmentPartialStore {
  /**
   * Load the ciphertext prefix for a non-zero download resume state.
   */
  load(resume: MediaAttachmentResumeState): Promise<Uint8Array | null>;
  /**
   * Persist the ciphertext prefix that matches the supplied resume offset.
   */
  save(resume: MediaAttachmentResumeState, bytes: Uint8Array): Promise<void>;
  /**
   * Remove a persisted ciphertext prefix. Implementations should make this
   * idempotent and non-throwing where possible because the transfer treats
   * cleanup as best-effort after stale prefixes, terminal failures, and
   * completed downloads.
   */
  clear?(resume: MediaAttachmentResumeState): Promise<void>;
}

export interface ByteRangeMediaAttachmentTransferOptions {
  fetch?: typeof fetch;
  chunkSizeBytes?: number;
  partialStore?: ByteRangeMediaAttachmentPartialStore;
  resumeToken?: string | ((url: string, options: MediaAttachmentTransferOptions) => string);
}

export interface MediaAttachmentRetryOptions {
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  enableJitter?: boolean;
}

export interface MediaAttachmentPolicy {
  maxPlaintextSizeBytes?: number;
  maxCiphertextSizeBytes?: number;
  allowedContentTypes?: readonly string[];
  maxFileNameLength?: number;
  maxCaptionLength?: number;
  maxWidth?: number;
  maxHeight?: number;
  maxDurationMs?: number;
  maxThumbnailBytes?: number;
  maxWaveformSamples?: number;
}

export const MEDIA_ATTACHMENT_POLICY_DEFAULTS = {
  maxPlaintextSizeBytes: 50 * 1024 * 1024,
  maxCiphertextSizeBytes: 64 * 1024 * 1024,
  maxFileNameLength: 255,
  maxCaptionLength: 4_096,
  maxWidth: 65_535,
  maxHeight: 65_535,
  maxDurationMs: 24 * 60 * 60 * 1_000,
  maxThumbnailBytes: 256 * 1024,
  maxWaveformSamples: 4_096,
} as const satisfies Required<Omit<MediaAttachmentPolicy, 'allowedContentTypes'>>;

export const MEDIA_ATTACHMENT_POLICY_PRESETS = {
  Image: {
    allowedContentTypes: ['image/*'],
    maxPlaintextSizeBytes: 25 * 1024 * 1024,
    maxCiphertextSizeBytes: 32 * 1024 * 1024,
    maxThumbnailBytes: 256 * 1024,
  },
  Video: {
    allowedContentTypes: ['video/*'],
    maxPlaintextSizeBytes: 100 * 1024 * 1024,
    maxCiphertextSizeBytes: 128 * 1024 * 1024,
    maxDurationMs: 4 * 60 * 60 * 1_000,
    maxThumbnailBytes: 512 * 1024,
  },
  Audio: {
    allowedContentTypes: ['audio/*'],
    maxPlaintextSizeBytes: 100 * 1024 * 1024,
    maxCiphertextSizeBytes: 128 * 1024 * 1024,
    maxDurationMs: 4 * 60 * 60 * 1_000,
    maxWaveformSamples: 4_096,
  },
  Document: {
    allowedContentTypes: ['application/pdf', 'text/*'],
    maxPlaintextSizeBytes: 50 * 1024 * 1024,
    maxCiphertextSizeBytes: 64 * 1024 * 1024,
  },
} as const satisfies Record<string, MediaAttachmentPolicy>;

export interface PrepareMediaAttachmentUploadOptions {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  /**
   * Stable idempotency key for this logical upload.
   *
   * Supply the same value when restarting an interrupted upload. The client
   * generates a random value when you omit it.
   */
  requestId?: string;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  policy?: MediaAttachmentPolicy;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
  contentType?: string;
  blurHash?: string;
  thumbnail?: string;
  width?: number;
  height?: number;
  durationMs?: number;
  waveform?: number[];
  fileName?: string;
  caption?: string;
  isViewOnce?: boolean;
  flags?: number;
  clientUuid?: string;
  cdnNumber?: number;
}

export interface ResolveMediaAttachmentOptions {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  policy?: MediaAttachmentPolicy;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
}

export interface ResolvedMediaAttachment {
  data: Uint8Array;
  attachment: MediaAttachmentPointer;
  contentType: string;
  size: number;
  fileName?: string;
  caption?: string;
  width?: number;
  height?: number;
  blurHash?: string;
  thumbnail?: string;
  durationMs?: number;
  waveform?: number[];
  isViewOnce?: boolean;
  flags?: number;
  storageId: string;
  digest: string;
  ciphertextSize: number;
}

export const MediaAttachmentCleanupReason = {
  ViewOnceOpened: 'view-once-opened',
  MessageDeleted: 'message-deleted',
  MessageExpired: 'message-expired',
  OrphanedUpload: 'orphaned-upload',
} as const;

export type MediaAttachmentCleanupReason =
  (typeof MediaAttachmentCleanupReason)[keyof typeof MediaAttachmentCleanupReason];

export interface MediaAttachmentCleanupPlan {
  storageId: string;
  attachmentId: string;
  reason: MediaAttachmentCleanupReason;
  deleteLocalCache: boolean;
  deleteRemoteBlob: boolean;
}

export interface MediaAttachmentOpenDecision {
  attachment: MediaAttachmentPointer;
  isViewOnce: boolean;
  cleanup: MediaAttachmentCleanupPlan | null;
  viewOnceOpenSync: { senderUserId: string; timestamp: number } | null;
}

export interface PlanMediaAttachmentOpenInput {
  attachment: CreateMediaAttachmentPointerInput;
  senderUserId: string;
  timestamp: number;
}

export type MediaAttachmentKnownIds = ReadonlySet<string> | readonly string[];

export interface PlanMediaAttachmentProcessingInput {
  attachment: CreateMediaAttachmentPointerInput;
  senderUserId: string;
  timestamp: number;
  processedDeliveryIds?: MediaAttachmentKnownIds;
  cachedAttachmentIds?: MediaAttachmentKnownIds;
  openedViewOnceDeliveryIds?: MediaAttachmentKnownIds;
  jobSource?: MediaAttachmentJobSource;
  jobPriority?: MediaAttachmentJobPriority;
  jobCreatedAt?: number;
  jobNotBefore?: number;
  jobAttempt?: number;
  resume?: MediaAttachmentResumeState;
}

export interface MediaAttachmentProcessingPlan {
  attachment: MediaAttachmentPointer;
  attachmentId: string;
  deliveryId: string;
  isDuplicateDelivery: boolean;
  hasLocalCopy: boolean;
  isViewOnceOpened: boolean;
  shouldPersistMessage: boolean;
  shouldDownload: boolean;
  downloadReason: 'new-delivery' | 'duplicate-missing-local-copy' | null;
  downloadJob: MediaAttachmentBackgroundJob | null;
  cleanup: MediaAttachmentCleanupPlan | null;
}

export interface MediaAttachmentDeleteSyncInput {
  storageId: string;
  attachmentId: string;
  reason: MediaAttachmentCleanupReason;
  deletedAt: number;
}

export interface PlanMediaAttachmentDeleteSyncInput {
  attachment: CreateMediaAttachmentPointerInput;
  reason: MediaAttachmentCleanupReason;
  deletedAt: number;
}

export const MediaAttachmentJobOperation = {
  Upload: 'upload',
  Download: 'download',
  DeleteLocal: 'delete-local',
  DeleteRemote: 'delete-remote',
  SyncDelete: 'sync-delete',
} as const;

export type MediaAttachmentJobOperation =
  (typeof MediaAttachmentJobOperation)[keyof typeof MediaAttachmentJobOperation];

export const MediaAttachmentJobSource = {
  ComposePreUpload: 'compose-pre-upload',
  IncomingMessage: 'incoming-message',
  SentSync: 'sent-sync',
  UserAction: 'user-action',
  Retry: 'retry',
  BackgroundRecovery: 'background-recovery',
  MessageDeleted: 'message-deleted',
  MessageExpired: 'message-expired',
  OrphanCleanup: 'orphan-cleanup',
  LinkedDeviceSync: 'linked-device-sync',
} as const;

export type MediaAttachmentJobSource =
  (typeof MediaAttachmentJobSource)[keyof typeof MediaAttachmentJobSource];

export const MediaAttachmentJobPriority = {
  High: 'high',
  Normal: 'normal',
  Low: 'low',
} as const;

export type MediaAttachmentJobPriority =
  (typeof MediaAttachmentJobPriority)[keyof typeof MediaAttachmentJobPriority];

export interface MediaAttachmentBackgroundJob {
  jobId: string;
  operation: MediaAttachmentJobOperation;
  source: MediaAttachmentJobSource;
  priority: MediaAttachmentJobPriority;
  requiresNetwork: boolean;
  attachmentId: string;
  storageId?: string;
  deliveryId?: string;
  reason?: string;
  attempt: number;
  createdAt: number;
  notBefore: number;
  resume?: MediaAttachmentResumeState;
}

export interface PlanMediaAttachmentUploadJobInput {
  localMediaId: string;
  /** Optional app-provided idempotency key for this logical upload. */
  requestId?: string;
  contentType: string;
  size: number;
  policy?: MediaAttachmentPolicy;
  source?: MediaAttachmentJobSource;
  priority?: MediaAttachmentJobPriority;
  createdAt?: number;
  notBefore?: number;
  attempt?: number;
  resume?: MediaAttachmentResumeState;
  fileName?: string;
  caption?: string;
  blurHash?: string;
  width?: number;
  height?: number;
  durationMs?: number;
  thumbnail?: string;
  waveform?: number[];
  isViewOnce?: boolean;
  flags?: number;
  clientUuid?: string;
  cdnNumber?: number;
}

export interface PlanMediaAttachmentDownloadJobInput extends PlanMediaAttachmentProcessingInput {
  source?: MediaAttachmentJobSource;
  priority?: MediaAttachmentJobPriority;
  createdAt?: number;
  notBefore?: number;
  attempt?: number;
  resume?: MediaAttachmentResumeState;
}

export interface PlanMediaAttachmentCleanupJobsInput {
  cleanup: MediaAttachmentCleanupPlan;
  source?: MediaAttachmentJobSource;
  priority?: MediaAttachmentJobPriority;
  createdAt?: number;
  notBefore?: number;
  attempt?: number;
  includeLocal?: boolean;
  includeRemote?: boolean;
  includeSync?: boolean;
}

export const MediaAttachmentJobExecutionStatus = {
  Completed: 'completed',
  Skipped: 'skipped',
} as const;

export type MediaAttachmentJobExecutionStatus =
  (typeof MediaAttachmentJobExecutionStatus)[keyof typeof MediaAttachmentJobExecutionStatus];

export type MediaAttachmentJobSkipReason =
  'missing-upload-data' | 'missing-attachment-pointer' | 'sync-delete-not-configured';

export interface MediaAttachmentUploadJobData {
  data: Uint8Array;
  options?: Omit<PrepareMediaAttachmentUploadOptions, 'remoteObjectStore'>;
}

export interface ExecuteMediaAttachmentJobOptions {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  policy?: MediaAttachmentPolicy;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  loadUploadData?: (
    job: MediaAttachmentBackgroundJob
  ) => Promise<MediaAttachmentUploadJobData | null>;
  loadAttachmentPointer?: (
    job: MediaAttachmentBackgroundJob
  ) => Promise<CreateMediaAttachmentPointerInput | null>;
  saveUploadedAttachment?: (
    job: MediaAttachmentBackgroundJob,
    attachment: MediaAttachmentPointer
  ) => Promise<void>;
  saveDownloadedAttachment?: (
    job: MediaAttachmentBackgroundJob,
    attachment: ResolvedMediaAttachment
  ) => Promise<void>;
  deleteLocalAttachment?: (job: MediaAttachmentBackgroundJob) => Promise<void>;
  syncDelete?: (
    job: MediaAttachmentBackgroundJob,
    deleteSync: MediaAttachmentDeleteSyncInput
  ) => Promise<void>;
}

export interface MediaAttachmentJobExecutionResult {
  job: MediaAttachmentBackgroundJob;
  status: MediaAttachmentJobExecutionStatus;
  skipReason?: MediaAttachmentJobSkipReason;
  uploadedAttachment?: MediaAttachmentPointer;
  downloadedAttachment?: ResolvedMediaAttachment;
  deleteSync?: MediaAttachmentDeleteSyncInput;
  deletedLocalCache?: boolean;
  deletedRemoteObject?: boolean;
}

export interface DeleteMediaAttachmentOptions {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
}

export interface DeleteMediaAttachmentResult {
  storageId: string;
  deletedRemoteObject: boolean;
}

function assertString(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`Invalid media attachment pointer: ${field} must be a non-empty string`);
  }
}

function assertBase64ByteLength(value: string, field: string, expectedBytes: number): void {
  try {
    const bytes = base64ToBytes(toBase64(value));
    if (bytes.length !== expectedBytes) {
      throw new Error(`expected ${expectedBytes} bytes, received ${bytes.length}`);
    }
  } catch (cause) {
    throw new TypeError(
      `Invalid media attachment pointer: ${field} must be a base64-encoded ${expectedBytes}-byte value`,
      { cause }
    );
  }
}

function assertBase64String(value: string, field: string): void {
  try {
    base64ToBytes(toBase64(value));
  } catch (cause) {
    throw new TypeError(
      `Invalid media attachment pointer: ${field} must be a base64-encoded value`,
      { cause }
    );
  }
}

function assertInteger(value: unknown, field: string, options?: { allowZero?: boolean }): void {
  const min = options?.allowZero ? 0 : 1;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) {
    throw new TypeError(`Invalid media attachment pointer: ${field} must be an integer >= ${min}`);
  }
}

function resolvePolicy(policy: MediaAttachmentPolicy | undefined): Required<MediaAttachmentPolicy> {
  return {
    ...MEDIA_ATTACHMENT_POLICY_DEFAULTS,
    allowedContentTypes: policy?.allowedContentTypes ?? [],
    ...policy,
  };
}

function assertPolicy(condition: boolean, message: string): void {
  if (!condition) {
    throw new MediaAttachmentError(message, MediaAttachmentErrorCode.PolicyViolation);
  }
}

function assertMetadataString(value: unknown, field: string): asserts value is string {
  assertPolicy(
    typeof value === 'string' && value.length > 0,
    `Media attachment ${field} must be a non-empty string`
  );
}

function assertOptionalMetadataString(value: unknown, field: string): void {
  if (value === undefined) return;
  assertMetadataString(value, field);
}

function assertOptionalMetadataInteger(
  value: unknown,
  field: string,
  options?: { allowZero?: boolean }
): void {
  if (value === undefined) return;
  const min = options?.allowZero ? 0 : 1;
  assertPolicy(
    typeof value === 'number' && Number.isSafeInteger(value) && value >= min,
    `Media attachment ${field} must be an integer >= ${min}`
  );
}

function assertOptionalMetadataBoolean(value: unknown, field: string): void {
  if (value === undefined) return;
  assertPolicy(typeof value === 'boolean', `Media attachment ${field} must be a boolean`);
}

function assertOptionalMetadataWaveform(value: unknown): asserts value is number[] | undefined {
  if (value === undefined) return;
  assertPolicy(
    Array.isArray(value) &&
      value.every(
        (sample) =>
          typeof sample === 'number' && Number.isSafeInteger(sample) && sample >= 0 && sample <= 255
      ),
    'Media attachment waveform must contain integer samples from 0 to 255'
  );
}

function isContentTypeAllowed(
  contentType: string,
  allowedContentTypes: readonly string[]
): boolean {
  if (allowedContentTypes.length === 0) return true;
  return allowedContentTypes.some((allowed) => {
    if (allowed.endsWith('/*')) {
      return contentType.startsWith(`${allowed.slice(0, -2)}/`);
    }
    return contentType === allowed;
  });
}

function validateMediaAttachmentMetadata(
  input: {
    contentType: string;
    size?: number;
    ciphertextSize?: number;
    fileName?: string;
    caption?: string;
    blurHash?: string;
    width?: number;
    height?: number;
    durationMs?: number;
    thumbnail?: string;
    waveform?: number[];
    isViewOnce?: boolean;
    flags?: number;
    clientUuid?: string;
    cdnNumber?: number;
  },
  policy: MediaAttachmentPolicy | undefined
): void {
  const resolvedPolicy = resolvePolicy(policy);

  assertMetadataString(input.contentType, 'contentType');
  assertOptionalMetadataString(input.fileName, 'fileName');
  assertOptionalMetadataString(input.caption, 'caption');
  assertOptionalMetadataString(input.blurHash, 'blurHash');
  assertOptionalMetadataString(input.thumbnail, 'thumbnail');
  assertOptionalMetadataString(input.clientUuid, 'clientUuid');
  assertOptionalMetadataInteger(input.size, 'size', { allowZero: true });
  assertOptionalMetadataInteger(input.ciphertextSize, 'ciphertextSize');
  assertOptionalMetadataInteger(input.width, 'width');
  assertOptionalMetadataInteger(input.height, 'height');
  assertOptionalMetadataInteger(input.durationMs, 'durationMs', {
    allowZero: true,
  });
  assertOptionalMetadataInteger(input.flags, 'flags', { allowZero: true });
  assertOptionalMetadataInteger(input.cdnNumber, 'cdnNumber');
  assertOptionalMetadataBoolean(input.isViewOnce, 'isViewOnce');
  assertOptionalMetadataWaveform(input.waveform);
  assertPolicy(
    input.clientUuid === undefined || UUID_PATTERN.test(input.clientUuid),
    'Media attachment clientUuid must be a UUID string'
  );
  assertPolicy(
    input.flags === undefined || isMediaAttachmentFlagSet(input.flags),
    'Media attachment flags contains unknown media flag bits'
  );

  assertPolicy(
    input.size === undefined || input.size <= resolvedPolicy.maxPlaintextSizeBytes,
    `Media attachment plaintext size ${input.size} exceeds limit ${resolvedPolicy.maxPlaintextSizeBytes}`
  );
  assertPolicy(
    input.ciphertextSize === undefined ||
      input.ciphertextSize <= resolvedPolicy.maxCiphertextSizeBytes,
    `Media attachment ciphertext size ${input.ciphertextSize} exceeds limit ${resolvedPolicy.maxCiphertextSizeBytes}`
  );
  assertPolicy(
    isContentTypeAllowed(input.contentType, resolvedPolicy.allowedContentTypes),
    `Media attachment content type ${input.contentType} is not allowed`
  );
  assertPolicy(
    input.fileName === undefined || input.fileName.length <= resolvedPolicy.maxFileNameLength,
    `Media attachment file name exceeds limit ${resolvedPolicy.maxFileNameLength}`
  );
  assertPolicy(
    input.caption === undefined || input.caption.length <= resolvedPolicy.maxCaptionLength,
    `Media attachment caption exceeds limit ${resolvedPolicy.maxCaptionLength}`
  );
  assertPolicy(
    input.width === undefined || input.width <= resolvedPolicy.maxWidth,
    `Media attachment width ${input.width} exceeds limit ${resolvedPolicy.maxWidth}`
  );
  assertPolicy(
    input.height === undefined || input.height <= resolvedPolicy.maxHeight,
    `Media attachment height ${input.height} exceeds limit ${resolvedPolicy.maxHeight}`
  );
  assertPolicy(
    input.durationMs === undefined || input.durationMs <= resolvedPolicy.maxDurationMs,
    `Media attachment duration ${input.durationMs} exceeds limit ${resolvedPolicy.maxDurationMs}`
  );
  assertPolicy(
    input.thumbnail === undefined ||
      getBase64ByteLength(input.thumbnail, 'thumbnail') <= resolvedPolicy.maxThumbnailBytes,
    `Media attachment thumbnail exceeds limit ${resolvedPolicy.maxThumbnailBytes}`
  );
  assertPolicy(
    input.waveform === undefined || input.waveform.length <= resolvedPolicy.maxWaveformSamples,
    `Media attachment waveform exceeds limit ${resolvedPolicy.maxWaveformSamples}`
  );
}

export function validateMediaAttachmentPolicy(
  attachment: CreateMediaAttachmentPointerInput,
  policy?: MediaAttachmentPolicy
): MediaAttachmentPointer {
  const pointer = createMediaAttachmentPointer(attachment);
  validateMediaAttachmentMetadata(pointer, policy);
  return pointer;
}

function copyOptionalString(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput,
  field: 'clientUuid' | 'blurHash' | 'thumbnail' | 'fileName' | 'caption'
): void {
  const value = source[field];
  if (value === undefined) return;
  assertString(value, field);
  target[field] = value;
}

function copyOptionalClientUuid(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput
): void {
  const value = source.clientUuid;
  if (value === undefined) return;
  assertString(value, 'clientUuid');
  if (!UUID_PATTERN.test(value)) {
    throw new TypeError('Invalid media attachment pointer: clientUuid must be a UUID string');
  }
  target.clientUuid = value;
}

function copyOptionalThumbnail(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput
): void {
  const value = source.thumbnail;
  if (value === undefined) return;
  assertString(value, 'thumbnail');
  assertBase64String(value, 'thumbnail');
  target.thumbnail = value;
}

function getBase64ByteLength(value: string, field: string): number {
  try {
    return base64ToBytes(toBase64(value)).length;
  } catch (cause) {
    throw new MediaAttachmentError(
      `Media attachment ${field} must be base64 encoded`,
      MediaAttachmentErrorCode.PolicyViolation,
      { cause }
    );
  }
}

function copyOptionalInteger(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput,
  field: 'cdnNumber' | 'width' | 'height' | 'durationMs' | 'flags'
): void {
  const value = source[field];
  if (value === undefined) return;
  assertInteger(value, field, { allowZero: field === 'durationMs' });
  target[field] = value;
}

function copyOptionalFlags(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput
): void {
  const value = source.flags;
  if (value === undefined) return;
  assertInteger(value, 'flags', { allowZero: true });
  if (!isMediaAttachmentFlagSet(value)) {
    throw new TypeError('Invalid media attachment pointer: flags contains unknown media flag bits');
  }
  target.flags = value;
}

function copyOptionalWaveform(
  target: Partial<MediaAttachmentPointer>,
  source: CreateMediaAttachmentPointerInput
): void {
  if (source.waveform === undefined) return;
  if (
    !Array.isArray(source.waveform) ||
    !source.waveform.every(
      (sample) =>
        typeof sample === 'number' && Number.isInteger(sample) && sample >= 0 && sample <= 255
    )
  ) {
    throw new TypeError(
      'Invalid media attachment pointer: waveform must contain integer samples from 0 to 255'
    );
  }
  target.waveform = [...source.waveform];
}

export function createMediaAttachmentPointer(
  input: CreateMediaAttachmentPointerInput
): MediaAttachmentPointer {
  assertString(input.storageId, 'storageId');
  assertString(input.key, 'key');
  assertString(input.digest, 'digest');
  assertBase64ByteLength(input.key, 'key', MEDIA_ATTACHMENT_KEY_BYTES);
  assertBase64ByteLength(input.digest, 'digest', MEDIA_ATTACHMENT_DIGEST_BYTES);
  assertString(input.contentType, 'contentType');
  assertInteger(input.segmentSize, 'segmentSize');
  assertInteger(input.ciphertextSize, 'ciphertextSize');
  assertInteger(input.size, 'size', { allowZero: true });
  assertInteger(input.uploadTimestamp, 'uploadTimestamp');

  const pointer: Partial<MediaAttachmentPointer> = {
    version: 1,
    storageId: input.storageId,
    key: input.key,
    digest: input.digest,
    segmentSize: input.segmentSize,
    ciphertextSize: input.ciphertextSize,
    contentType: input.contentType,
    size: input.size,
    uploadTimestamp: input.uploadTimestamp,
  };

  copyOptionalClientUuid(pointer, input);
  copyOptionalString(pointer, input, 'blurHash');
  copyOptionalThumbnail(pointer, input);
  copyOptionalString(pointer, input, 'fileName');
  copyOptionalString(pointer, input, 'caption');
  copyOptionalInteger(pointer, input, 'cdnNumber');
  copyOptionalInteger(pointer, input, 'width');
  copyOptionalInteger(pointer, input, 'height');
  copyOptionalInteger(pointer, input, 'durationMs');
  copyOptionalFlags(pointer, input);
  copyOptionalWaveform(pointer, input);

  if (input.isViewOnce !== undefined) {
    if (typeof input.isViewOnce !== 'boolean') {
      throw new TypeError('Invalid media attachment pointer: isViewOnce must be a boolean');
    }
    pointer.isViewOnce = input.isViewOnce;
  }

  return pointer as MediaAttachmentPointer;
}

function encodeAttachmentIdentityPart(value: string): string {
  return bytesToUrlSafeBase64(new TextEncoder().encode(value));
}

export function createMediaAttachmentId(attachment: CreateMediaAttachmentPointerInput): string {
  const pointer = createMediaAttachmentPointer(attachment);
  return [
    'media-v1',
    encodeAttachmentIdentityPart(pointer.storageId),
    pointer.ciphertextSize,
    encodeAttachmentIdentityPart(pointer.digest),
  ].join('.');
}

export function createMediaAttachmentDeliveryId(input: {
  attachment: CreateMediaAttachmentPointerInput;
  senderUserId: string;
  timestamp: number;
}): string {
  assertString(input.senderUserId, 'senderUserId');
  assertInteger(input.timestamp, 'timestamp');
  return [
    'media-delivery-v1',
    encodeAttachmentIdentityPart(input.senderUserId),
    input.timestamp,
    createMediaAttachmentId(input.attachment),
  ].join('.');
}

function knownIdsIncludes(ids: MediaAttachmentKnownIds | undefined, id: string): boolean {
  if (!ids) return false;
  const candidate = ids as { has?: unknown };
  if (typeof candidate.has === 'function') {
    return (candidate.has as (value: string) => boolean)(id);
  }
  return (ids as readonly string[]).includes(id);
}

function assertMediaAttachmentCleanupReason(
  reason: MediaAttachmentCleanupReason
): asserts reason is MediaAttachmentCleanupReason {
  if (!isMediaAttachmentCleanupReason(reason)) {
    throw new TypeError('Invalid media attachment cleanup reason');
  }
}

function isMediaAttachmentCleanupReason(value: unknown): value is MediaAttachmentCleanupReason {
  return (
    value === MediaAttachmentCleanupReason.ViewOnceOpened ||
    value === MediaAttachmentCleanupReason.MessageDeleted ||
    value === MediaAttachmentCleanupReason.MessageExpired ||
    value === MediaAttachmentCleanupReason.OrphanedUpload
  );
}

function assertMediaAttachmentJobSource(source: MediaAttachmentJobSource): void {
  if (!Object.values(MediaAttachmentJobSource).includes(source)) {
    throw new TypeError('Invalid media attachment job source');
  }
}

function assertMediaAttachmentJobPriority(priority: MediaAttachmentJobPriority): void {
  if (!Object.values(MediaAttachmentJobPriority).includes(priority)) {
    throw new TypeError('Invalid media attachment job priority');
  }
}

function createMediaAttachmentBackgroundJob(input: {
  operation: MediaAttachmentJobOperation;
  source: MediaAttachmentJobSource;
  priority?: MediaAttachmentJobPriority;
  requiresNetwork: boolean;
  attachmentId: string;
  storageId?: string;
  deliveryId?: string;
  reason?: string;
  attempt?: number;
  createdAt?: number;
  notBefore?: number;
  resume?: MediaAttachmentResumeState;
}): MediaAttachmentBackgroundJob {
  assertString(input.attachmentId, 'attachmentId');
  assertMediaAttachmentJobSource(input.source);
  const priority = input.priority ?? MediaAttachmentJobPriority.Normal;
  assertMediaAttachmentJobPriority(priority);
  const attempt = input.attempt ?? 0;
  const createdAt = input.createdAt ?? Date.now();
  const notBefore = input.notBefore ?? createdAt;
  assertInteger(attempt, 'attempt', { allowZero: true });
  assertInteger(createdAt, 'createdAt', { allowZero: true });
  assertInteger(notBefore, 'notBefore', { allowZero: true });

  const jobId = [
    'media-job-v1',
    input.operation,
    encodeAttachmentIdentityPart(input.attachmentId),
    input.deliveryId ? encodeAttachmentIdentityPart(input.deliveryId) : 'none',
    input.reason ? encodeAttachmentIdentityPart(input.reason) : 'none',
  ].join('.');

  return {
    jobId,
    operation: input.operation,
    source: input.source,
    priority,
    requiresNetwork: input.requiresNetwork,
    attachmentId: input.attachmentId,
    storageId: input.storageId,
    deliveryId: input.deliveryId,
    reason: input.reason,
    attempt,
    createdAt,
    notBefore,
    resume: input.resume,
  };
}

export function planMediaAttachmentUploadJob(
  input: PlanMediaAttachmentUploadJobInput
): MediaAttachmentBackgroundJob {
  assertString(input.localMediaId, 'localMediaId');
  assertString(input.contentType, 'contentType');
  assertInteger(input.size, 'size', { allowZero: true });
  validateMediaAttachmentMetadata(
    {
      contentType: input.contentType,
      size: input.size,
      fileName: input.fileName,
      caption: input.caption,
      blurHash: input.blurHash,
      width: input.width,
      height: input.height,
      durationMs: input.durationMs,
      thumbnail: input.thumbnail,
      waveform: input.waveform,
      isViewOnce: input.isViewOnce,
      flags: input.flags,
      clientUuid: input.clientUuid,
      cdnNumber: input.cdnNumber,
    },
    input.policy
  );

  return createMediaAttachmentBackgroundJob({
    operation: MediaAttachmentJobOperation.Upload,
    source: input.source ?? MediaAttachmentJobSource.ComposePreUpload,
    priority: input.priority ?? MediaAttachmentJobPriority.Normal,
    requiresNetwork: true,
    attachmentId: `upload-v1.${encodeAttachmentIdentityPart(input.localMediaId)}`,
    reason: input.contentType,
    attempt: input.attempt,
    createdAt: input.createdAt,
    notBefore: input.notBefore,
    resume: input.resume,
  });
}

export function planMediaAttachmentCleanup(
  attachment: CreateMediaAttachmentPointerInput,
  reason: MediaAttachmentCleanupReason
): MediaAttachmentCleanupPlan {
  assertMediaAttachmentCleanupReason(reason);
  const pointer = createMediaAttachmentPointer(attachment);
  return {
    storageId: pointer.storageId,
    attachmentId: createMediaAttachmentId(pointer),
    reason,
    deleteLocalCache: true,
    deleteRemoteBlob:
      reason === MediaAttachmentCleanupReason.MessageDeleted ||
      reason === MediaAttachmentCleanupReason.MessageExpired ||
      reason === MediaAttachmentCleanupReason.OrphanedUpload,
  };
}

export function planMediaAttachmentCleanupJobs(
  input: PlanMediaAttachmentCleanupJobsInput
): MediaAttachmentBackgroundJob[] {
  const source = input.source ?? MediaAttachmentJobSource.BackgroundRecovery;
  const includeLocal = input.includeLocal ?? input.cleanup.deleteLocalCache;
  const includeRemote = input.includeRemote ?? input.cleanup.deleteRemoteBlob;
  const includeSync = input.includeSync ?? false;
  const jobs: MediaAttachmentBackgroundJob[] = [];

  if (includeLocal) {
    jobs.push(
      createMediaAttachmentBackgroundJob({
        operation: MediaAttachmentJobOperation.DeleteLocal,
        source,
        priority: input.priority ?? MediaAttachmentJobPriority.Normal,
        requiresNetwork: false,
        attachmentId: input.cleanup.attachmentId,
        storageId: input.cleanup.storageId,
        reason: input.cleanup.reason,
        attempt: input.attempt,
        createdAt: input.createdAt,
        notBefore: input.notBefore,
      })
    );
  }

  if (includeRemote) {
    jobs.push(
      createMediaAttachmentBackgroundJob({
        operation: MediaAttachmentJobOperation.DeleteRemote,
        source,
        priority: input.priority ?? MediaAttachmentJobPriority.Normal,
        requiresNetwork: true,
        attachmentId: input.cleanup.attachmentId,
        storageId: input.cleanup.storageId,
        reason: input.cleanup.reason,
        attempt: input.attempt,
        createdAt: input.createdAt,
        notBefore: input.notBefore,
      })
    );
  }

  if (includeSync) {
    jobs.push(
      createMediaAttachmentBackgroundJob({
        operation: MediaAttachmentJobOperation.SyncDelete,
        source: MediaAttachmentJobSource.LinkedDeviceSync,
        priority: input.priority ?? MediaAttachmentJobPriority.Normal,
        requiresNetwork: true,
        attachmentId: input.cleanup.attachmentId,
        storageId: input.cleanup.storageId,
        reason: input.cleanup.reason,
        attempt: input.attempt,
        createdAt: input.createdAt,
        notBefore: input.notBefore,
      })
    );
  }

  return jobs;
}

export function planMediaAttachmentOpen(
  input: PlanMediaAttachmentOpenInput
): MediaAttachmentOpenDecision {
  const attachment = createMediaAttachmentPointer(input.attachment);
  assertString(input.senderUserId, 'senderUserId');
  assertInteger(input.timestamp, 'timestamp');

  if (!attachment.isViewOnce) {
    return {
      attachment,
      isViewOnce: false,
      cleanup: null,
      viewOnceOpenSync: null,
    };
  }

  return {
    attachment,
    isViewOnce: true,
    cleanup: planMediaAttachmentCleanup(attachment, MediaAttachmentCleanupReason.ViewOnceOpened),
    viewOnceOpenSync: {
      senderUserId: input.senderUserId,
      timestamp: input.timestamp,
    },
  };
}

export function planMediaAttachmentProcessing(
  input: PlanMediaAttachmentProcessingInput
): MediaAttachmentProcessingPlan {
  const attachment = createMediaAttachmentPointer(input.attachment);
  assertString(input.senderUserId, 'senderUserId');
  assertInteger(input.timestamp, 'timestamp');

  const attachmentId = createMediaAttachmentId(attachment);
  const deliveryId = createMediaAttachmentDeliveryId({
    attachment,
    senderUserId: input.senderUserId,
    timestamp: input.timestamp,
  });
  const isDuplicateDelivery = knownIdsIncludes(input.processedDeliveryIds, deliveryId);
  const hasLocalCopy = knownIdsIncludes(input.cachedAttachmentIds, attachmentId);
  const isViewOnceOpened =
    attachment.isViewOnce === true && knownIdsIncludes(input.openedViewOnceDeliveryIds, deliveryId);
  const shouldDownload = !hasLocalCopy && !isViewOnceOpened;
  const downloadReason = shouldDownload
    ? isDuplicateDelivery
      ? 'duplicate-missing-local-copy'
      : 'new-delivery'
    : null;

  return {
    attachment,
    attachmentId,
    deliveryId,
    isDuplicateDelivery,
    hasLocalCopy,
    isViewOnceOpened,
    shouldPersistMessage: !isDuplicateDelivery,
    shouldDownload,
    downloadReason,
    downloadJob:
      shouldDownload && downloadReason
        ? createMediaAttachmentBackgroundJob({
            operation: MediaAttachmentJobOperation.Download,
            source: input.jobSource ?? MediaAttachmentJobSource.IncomingMessage,
            priority: input.jobPriority ?? MediaAttachmentJobPriority.Normal,
            requiresNetwork: true,
            attachmentId,
            storageId: attachment.storageId,
            deliveryId,
            reason: downloadReason,
            attempt: input.jobAttempt,
            createdAt: input.jobCreatedAt ?? input.timestamp,
            notBefore: input.jobNotBefore ?? input.jobCreatedAt ?? input.timestamp,
            resume: input.resume,
          })
        : null,
    cleanup: isViewOnceOpened
      ? planMediaAttachmentCleanup(attachment, MediaAttachmentCleanupReason.ViewOnceOpened)
      : null,
  };
}

export function planMediaAttachmentDownloadJob(
  input: PlanMediaAttachmentDownloadJobInput
): MediaAttachmentBackgroundJob | null {
  return planMediaAttachmentProcessing({
    ...input,
    jobSource: input.source ?? MediaAttachmentJobSource.IncomingMessage,
    jobPriority: input.priority ?? MediaAttachmentJobPriority.Normal,
    jobCreatedAt: input.createdAt,
    jobNotBefore: input.notBefore,
    jobAttempt: input.attempt,
    resume: input.resume,
  }).downloadJob;
}

export function planMediaAttachmentDeleteSync(
  input: PlanMediaAttachmentDeleteSyncInput
): MediaAttachmentDeleteSyncInput {
  assertInteger(input.deletedAt, 'deletedAt');
  assertMediaAttachmentCleanupReason(input.reason);
  const attachment = createMediaAttachmentPointer(input.attachment);
  return {
    storageId: attachment.storageId,
    attachmentId: createMediaAttachmentId(attachment),
    reason: input.reason,
    deletedAt: input.deletedAt,
  };
}

function requireMediaAttachmentJobHandler<T>(
  handler: T | undefined,
  name: string,
  operation: MediaAttachmentJobOperation
): T {
  if (handler !== undefined) return handler;
  throw new MediaAttachmentError(
    `Cannot execute media attachment ${operation} job: ${name} handler is required`,
    MediaAttachmentErrorCode.JobHandlerMissing
  );
}

function completedMediaAttachmentJob(
  job: MediaAttachmentBackgroundJob,
  result: Omit<MediaAttachmentJobExecutionResult, 'job' | 'status'> = {}
): MediaAttachmentJobExecutionResult {
  return {
    job,
    status: MediaAttachmentJobExecutionStatus.Completed,
    ...result,
  };
}

function skippedMediaAttachmentJob(
  job: MediaAttachmentBackgroundJob,
  skipReason: MediaAttachmentJobSkipReason
): MediaAttachmentJobExecutionResult {
  return {
    job,
    status: MediaAttachmentJobExecutionStatus.Skipped,
    skipReason,
  };
}

async function loadRequiredAttachmentPointer(
  job: MediaAttachmentBackgroundJob,
  options: ExecuteMediaAttachmentJobOptions
): Promise<MediaAttachmentPointer | null> {
  const loadAttachmentPointer = requireMediaAttachmentJobHandler(
    options.loadAttachmentPointer,
    'loadAttachmentPointer',
    job.operation
  );
  const attachment = await loadAttachmentPointer(job);
  return attachment ? createMediaAttachmentPointer(attachment) : null;
}

export async function executeMediaAttachmentJob(
  job: MediaAttachmentBackgroundJob,
  options: ExecuteMediaAttachmentJobOptions
): Promise<MediaAttachmentJobExecutionResult> {
  switch (job.operation) {
    case MediaAttachmentJobOperation.Upload: {
      const loadUploadData = requireMediaAttachmentJobHandler(
        options.loadUploadData,
        'loadUploadData',
        job.operation
      );
      const uploadData = await loadUploadData(job);
      if (!uploadData) {
        return skippedMediaAttachmentJob(job, 'missing-upload-data');
      }
      const attachment = await prepareMediaAttachmentUpload(uploadData.data, {
        ...uploadData.options,
        remoteObjectStore: options.remoteObjectStore,
        transfer: uploadData.options?.transfer ?? options.transfer,
        retry: uploadData.options?.retry ?? options.retry,
        policy: uploadData.options?.policy ?? options.policy,
        signal: uploadData.options?.signal ?? options.signal,
        onProgress: uploadData.options?.onProgress ?? options.onProgress,
        onCheckpoint: uploadData.options?.onCheckpoint ?? options.onCheckpoint,
        resume: uploadData.options?.resume ?? job.resume,
      });
      await options.saveUploadedAttachment?.(job, attachment);
      return completedMediaAttachmentJob(job, {
        uploadedAttachment: attachment,
      });
    }

    case MediaAttachmentJobOperation.Download: {
      const attachment = await loadRequiredAttachmentPointer(job, options);
      if (!attachment) {
        return skippedMediaAttachmentJob(job, 'missing-attachment-pointer');
      }
      const downloadedAttachment = await resolveMediaAttachment(attachment, {
        remoteObjectStore: options.remoteObjectStore,
        transfer: options.transfer,
        retry: options.retry,
        policy: options.policy,
        signal: options.signal,
        onProgress: options.onProgress,
        onCheckpoint: options.onCheckpoint,
        resume: job.resume,
      });
      await options.saveDownloadedAttachment?.(job, downloadedAttachment);
      return completedMediaAttachmentJob(job, { downloadedAttachment });
    }

    case MediaAttachmentJobOperation.DeleteLocal: {
      const deleteLocalAttachment = requireMediaAttachmentJobHandler(
        options.deleteLocalAttachment,
        'deleteLocalAttachment',
        job.operation
      );
      await deleteLocalAttachment(job);
      return completedMediaAttachmentJob(job, { deletedLocalCache: true });
    }

    case MediaAttachmentJobOperation.DeleteRemote: {
      const attachment = await loadRequiredAttachmentPointer(job, options);
      if (!attachment) {
        return skippedMediaAttachmentJob(job, 'missing-attachment-pointer');
      }
      const result = await deleteMediaAttachment(attachment, {
        remoteObjectStore: options.remoteObjectStore,
        signal: options.signal,
        onProgress: options.onProgress,
      });
      return completedMediaAttachmentJob(job, {
        deletedRemoteObject: result.deletedRemoteObject,
      });
    }

    case MediaAttachmentJobOperation.SyncDelete: {
      if (!options.syncDelete) {
        return skippedMediaAttachmentJob(job, 'sync-delete-not-configured');
      }
      const attachment = await loadRequiredAttachmentPointer(job, options);
      if (!attachment) {
        return skippedMediaAttachmentJob(job, 'missing-attachment-pointer');
      }
      const deleteSync = planMediaAttachmentDeleteSync({
        attachment,
        reason: isMediaAttachmentCleanupReason(job.reason)
          ? job.reason
          : MediaAttachmentCleanupReason.MessageDeleted,
        deletedAt: Date.now(),
      });
      await options.syncDelete(job, deleteSync);
      return completedMediaAttachmentJob(job, { deleteSync });
    }
  }
}

export function createMediaAttachmentMessage(input: {
  attachment: CreateMediaAttachmentPointerInput;
  timestamp: number;
}): MediaAttachmentMessage {
  assertInteger(input.timestamp, 'timestamp');
  return {
    type: MediaAttachmentMessageType.Attachment,
    version: 1,
    timestamp: input.timestamp,
    attachment: createMediaAttachmentPointer(input.attachment),
  };
}

export function serializeMediaAttachmentMessage(input: {
  attachment: CreateMediaAttachmentPointerInput;
  timestamp: number;
}): string {
  return JSON.stringify(createMediaAttachmentMessage(input));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertNotAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw new MediaAttachmentError(
    'Media attachment operation cancelled',
    MediaAttachmentErrorCode.Cancelled,
    { cause: signal.reason }
  );
}

function emitProgress(
  onProgress: MediaAttachmentProgressCallback | undefined,
  progress: MediaAttachmentProgress
): void {
  onProgress?.(progress);
}

function emitCheckpoint(
  onCheckpoint: MediaAttachmentCheckpointCallback | undefined,
  checkpoint: Omit<MediaAttachmentTransferCheckpoint, 'updatedAt'>
): void {
  onCheckpoint?.({
    ...checkpoint,
    updatedAt: Date.now(),
  });
}

function createResumeStateFromCheckpoint(
  checkpoint: MediaAttachmentTransferCheckpoint,
  previous: MediaAttachmentResumeState | undefined
): MediaAttachmentResumeState | undefined {
  if (checkpoint.phase !== 'transfer') {
    return previous;
  }

  const offsetBytes = Number.isInteger(checkpoint.bytesTransferred)
    ? Math.max(checkpoint.bytesTransferred ?? 0, 0)
    : previous?.offsetBytes;
  const resumeToken = checkpoint.resumeToken ?? previous?.resumeToken;

  if (offsetBytes === undefined && resumeToken === undefined) {
    return previous;
  }

  return {
    operation: checkpoint.operation,
    ...(offsetBytes !== undefined ? { offsetBytes } : {}),
    ...(resumeToken !== undefined ? { resumeToken } : {}),
    updatedAt: checkpoint.updatedAt,
    ...(previous?.expiresAt !== undefined ? { expiresAt: previous.expiresAt } : {}),
  };
}

function trackResumeCheckpoints(
  operation: MediaAttachmentResumeState['operation'],
  onCheckpoint: MediaAttachmentCheckpointCallback | undefined,
  setResume: (resume: MediaAttachmentResumeState | undefined) => void,
  getResume: () => MediaAttachmentResumeState | undefined
): MediaAttachmentCheckpointCallback {
  return (checkpoint) => {
    if (checkpoint.operation === operation) {
      const nextResume = createResumeStateFromCheckpoint(checkpoint, getResume());
      if (nextResume !== getResume()) {
        setResume(nextResume);
      }
    }

    onCheckpoint?.(checkpoint);
  };
}

export function parseMediaAttachmentMessage(plaintext: string): MediaAttachmentMessage | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;
  if (parsed.type !== MediaAttachmentMessageType.Attachment) return null;
  if (parsed.version !== 1) return null;
  if (typeof parsed.timestamp !== 'number') return null;
  if (!isRecord(parsed.attachment)) return null;

  try {
    return createMediaAttachmentMessage({
      timestamp: parsed.timestamp,
      attachment: parsed.attachment as unknown as CreateMediaAttachmentPointerInput,
    });
  } catch {
    return null;
  }
}

async function defaultUpload(
  url: string,
  data: Uint8Array,
  options: MediaAttachmentTransferOptions = {}
): Promise<MediaAttachmentUploadResponse> {
  assertNotAborted(options.signal);
  if (typeof globalThis.fetch !== 'function') {
    throw new MediaAttachmentError(
      'Cannot upload media attachment: fetch is not available',
      MediaAttachmentErrorCode.UploadFailed
    );
  }

  emitProgress(options.onProgress, {
    operation: 'upload',
    phase: 'transfer',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    bytesTransferred: 0,
    totalBytes: options.totalBytes ?? data.length,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'upload',
    phase: 'transfer',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred: 0,
    totalBytes: options.totalBytes ?? data.length,
    resumeToken: options.resume?.resumeToken,
  });

  const body = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const response = await globalThis.fetch(url, {
    method: 'PUT',
    body,
    signal: options.signal,
    headers: {
      'Content-Type': 'application/octet-stream',
      ...options.headers,
    },
  });
  assertNotAborted(options.signal);

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      statusText: response.statusText,
    };
  }

  emitProgress(options.onProgress, {
    operation: 'upload',
    phase: 'transfer',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    bytesTransferred: data.length,
    totalBytes: options.totalBytes ?? data.length,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'upload',
    phase: 'complete',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred: data.length,
    totalBytes: options.totalBytes ?? data.length,
    resumeToken: options.resume?.resumeToken,
  });

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
  };
}

function getFetchImplementation(
  fetchOverride: typeof fetch | undefined,
  operation: 'upload' | 'download' = 'upload'
): typeof fetch {
  const fetchImpl = fetchOverride ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new MediaAttachmentError(
      `Cannot ${operation} media attachment: fetch is not available`,
      operation === 'upload'
        ? MediaAttachmentErrorCode.UploadFailed
        : MediaAttachmentErrorCode.DownloadFailed
    );
  }
  return fetchImpl;
}

function getHeader(response: Response, header: string): string | null {
  return response.headers?.get?.(header) ?? response.headers?.get?.(header.toLowerCase()) ?? null;
}

function parseTusOffset(value: string | null, context: string): number {
  if (value === null) {
    throwInvalidResumeState(`TUS media upload ${context} did not return Upload-Offset`);
  }

  const normalized = value.trim();
  if (!/^\d+$/.test(normalized)) {
    throwInvalidResumeState(`TUS media upload ${context} returned malformed Upload-Offset`);
  }

  const offset = Number(normalized);
  if (!Number.isSafeInteger(offset)) {
    throwInvalidResumeState(`TUS media upload ${context} returned unsafe Upload-Offset`);
  }

  return offset;
}

function parseTusCreationOffset(value: string | null, totalBytes: number): number {
  if (value === null) return 0;
  return assertTusOffsetWithinUpload(parseTusOffset(value, 'creation response'), totalBytes);
}

function assertTusOffsetWithinUpload(offset: number, totalBytes: number): number {
  if (offset > totalBytes) {
    throwInvalidResumeState(
      `TUS media upload returned Upload-Offset ${offset} beyond ${totalBytes} byte upload`
    );
  }
  return offset;
}

function assertTusPatchAdvancedToExpectedOffset(offset: number, expectedOffset: number): number {
  if (offset !== expectedOffset) {
    throwInvalidResumeState(
      `TUS media upload resume offset is invalid: expected ${expectedOffset}, received ${offset}`
    );
  }
  return offset;
}

function assertTusUploadResumeState(resume: MediaAttachmentResumeState | undefined): void {
  if (!resume) return;
  if (resume.operation !== 'upload') {
    throwInvalidResumeState('TUS media upload received non-upload resume state');
  }
  if (
    resume.offsetBytes !== undefined &&
    (!Number.isSafeInteger(resume.offsetBytes) || resume.offsetBytes < 0)
  ) {
    throwInvalidResumeState('TUS media upload resume offset is invalid');
  }
}

function resolveTusChunkSizeBytes(
  chunkSizeBytes: number | undefined,
  payloadBytes: number
): number {
  const resolved = chunkSizeBytes ?? payloadBytes;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new MediaAttachmentError(
      'TUS media upload chunk size must be a positive safe integer',
      MediaAttachmentErrorCode.UploadFailed
    );
  }
  return resolved;
}

function resolveTusLocation(location: string | null, creationUrl: string): string {
  if (!location) {
    throw new MediaAttachmentError(
      'TUS media upload did not return a resume location',
      MediaAttachmentErrorCode.UploadFailed
    );
  }
  return new URL(location, creationUrl).toString();
}

function isInvalidTusResumeResponse(response: Response): boolean {
  return (
    response.status === 400 ||
    response.status === 404 ||
    response.status === 409 ||
    response.status === 410
  );
}

function throwInvalidResumeState(message: string, status?: number): never {
  throw new MediaAttachmentError(message, MediaAttachmentErrorCode.ResumeStateInvalid, { status });
}

function sliceBytes(data: Uint8Array, start: number, end?: number): ArrayBuffer {
  const view = data.subarray(start, end);
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

function emitUploadTransferProgress(
  options: MediaAttachmentTransferOptions,
  bytesTransferred: number,
  totalBytes: number,
  resumeToken?: string
): void {
  emitProgress(options.onProgress, {
    operation: 'upload',
    phase: 'transfer',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    bytesTransferred,
    totalBytes,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'upload',
    phase: bytesTransferred >= totalBytes ? 'complete' : 'transfer',
    attempt: options.attempt,
    requestId: options.requestId,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred,
    totalBytes,
    resumeToken,
  });
}

export function createTusMediaAttachmentTransfer(
  tusOptions: TusMediaAttachmentTransferOptions = {}
): MediaAttachmentTransfer {
  return {
    async upload(
      creationUrl: string,
      data: Uint8Array,
      options: MediaAttachmentTransferOptions = {}
    ): Promise<MediaAttachmentUploadResponse> {
      assertNotAborted(options.signal);
      const fetchImpl = getFetchImplementation(tusOptions.fetch);
      const tusVersion = tusOptions.tusVersion ?? '1.0.0';
      const totalBytes = options.totalBytes ?? data.length;
      if (totalBytes !== data.length) {
        throw new MediaAttachmentError(
          `TUS media upload length mismatch: totalBytes ${totalBytes} does not match payload length ${data.length}`,
          MediaAttachmentErrorCode.UploadFailed
        );
      }
      assertTusUploadResumeState(options.resume);
      const chunkSizeBytes = resolveTusChunkSizeBytes(tusOptions.chunkSizeBytes, data.length);
      let resumeUrl = options.resume?.resumeToken;
      let offset = options.resume?.offsetBytes ?? 0;

      if (resumeUrl) {
        const head = await fetchImpl(resumeUrl, {
          method: 'HEAD',
          signal: options.signal,
          headers: {
            ...options.headers,
            'Tus-Resumable': tusVersion,
          },
        });
        assertNotAborted(options.signal);
        if (!head.ok) {
          if (isInvalidTusResumeResponse(head)) {
            throwInvalidResumeState('TUS media upload resume location is invalid', head.status);
          }
          return {
            ok: false,
            status: head.status,
            statusText: head.statusText,
          };
        }
        offset = assertTusOffsetWithinUpload(
          parseTusOffset(getHeader(head, 'Upload-Offset'), 'resume response'),
          totalBytes
        );
      } else {
        const create = await fetchImpl(creationUrl, {
          method: 'POST',
          signal: options.signal,
          headers: {
            ...options.headers,
            'Tus-Resumable': tusVersion,
            'Upload-Length': String(totalBytes),
          },
        });
        assertNotAborted(options.signal);
        if (create.status !== 201) {
          return {
            ok: false,
            status: create.status,
            statusText: create.statusText,
          };
        }
        resumeUrl = resolveTusLocation(getHeader(create, 'Location'), creationUrl);
        offset = parseTusCreationOffset(getHeader(create, 'Upload-Offset'), totalBytes);
      }

      emitUploadTransferProgress(options, offset, totalBytes, resumeUrl);

      while (offset < data.length) {
        assertNotAborted(options.signal);
        const nextOffset = Math.min(offset + chunkSizeBytes, data.length);
        const patch = await fetchImpl(resumeUrl, {
          method: 'PATCH',
          body: sliceBytes(data, offset, nextOffset),
          signal: options.signal,
          headers: {
            ...options.headers,
            'Tus-Resumable': tusVersion,
            'Upload-Offset': String(offset),
            'Content-Type': 'application/offset+octet-stream',
          },
        });
        assertNotAborted(options.signal);
        if (!patch.ok) {
          if (isInvalidTusResumeResponse(patch)) {
            throwInvalidResumeState('TUS media upload resume offset is invalid', patch.status);
          }
          return {
            ok: false,
            status: patch.status,
            statusText: patch.statusText,
          };
        }
        offset = assertTusPatchAdvancedToExpectedOffset(
          assertTusOffsetWithinUpload(
            parseTusOffset(getHeader(patch, 'Upload-Offset'), 'PATCH response'),
            totalBytes
          ),
          nextOffset
        );
        emitUploadTransferProgress(options, offset, totalBytes, resumeUrl);
      }

      return { ok: true, status: 204, statusText: 'No Content' };
    },
  };
}

interface ParsedContentRange {
  start: number;
  end: number;
  totalBytes?: number;
}

function parseContentLength(response: Response): number | undefined {
  const contentLength = getHeader(response, 'content-length');
  if (!contentLength || !/^\d+$/.test(contentLength)) return undefined;
  return Number(contentLength);
}

function assertCiphertextSizeWithinExpected(
  expectedBytes: number | undefined,
  receivedBytes: number
): void {
  if (expectedBytes === undefined || receivedBytes <= expectedBytes) {
    return;
  }

  throw new MediaAttachmentError(
    `Media attachment ciphertext size mismatch: expected ${expectedBytes} bytes, received ${receivedBytes}`,
    MediaAttachmentErrorCode.CiphertextSizeMismatch
  );
}

function assertCiphertextSizeEqualsExpected(
  expectedBytes: number | undefined,
  receivedBytes: number | undefined
): void {
  if (
    expectedBytes === undefined ||
    receivedBytes === undefined ||
    receivedBytes === expectedBytes
  ) {
    return;
  }

  throw new MediaAttachmentError(
    `Media attachment ciphertext size mismatch: expected ${expectedBytes} bytes, received ${receivedBytes}`,
    MediaAttachmentErrorCode.CiphertextSizeMismatch
  );
}

function parseContentRange(value: string | null): ParsedContentRange | null {
  if (!value) return null;
  const match = /^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i.exec(value.trim());
  if (!match) return null;

  const start = Number(match[1]);
  const end = Number(match[2]);
  const totalBytes = match[3] === '*' ? undefined : Number(match[3]);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
    return null;
  }
  if (totalBytes !== undefined && (!Number.isSafeInteger(totalBytes) || totalBytes <= end)) {
    return null;
  }
  return { start, end, totalBytes };
}

function contentRangeLength(range: ParsedContentRange): number {
  return range.end - range.start + 1;
}

function assertContentRangeTotalMatchesExpected(
  range: ParsedContentRange,
  expectedBytes: number | undefined
): void {
  assertCiphertextSizeEqualsExpected(expectedBytes, range.totalBytes);
}

function assertContentRangeBodyLength(range: ParsedContentRange, bytes: Uint8Array): void {
  const expectedLength = contentRangeLength(range);
  if (bytes.length === expectedLength) {
    return;
  }

  throw new MediaAttachmentError(
    `Media attachment range body length mismatch: expected ${expectedLength} bytes, received ${bytes.length}`,
    MediaAttachmentErrorCode.DownloadFailed,
    { status: 206 }
  );
}

async function readResponseBodyBytes(response: Response, signal: AbortSignal | undefined) {
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      assertNotAborted(signal);
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    return concatBytes(...chunks);
  }

  const data = new Uint8Array(await response.arrayBuffer());
  assertNotAborted(signal);
  return data;
}

function resolveByteRangeResumeToken(
  url: string,
  options: MediaAttachmentTransferOptions,
  rangeOptions: ByteRangeMediaAttachmentTransferOptions
): string {
  if (options.resume?.resumeToken) return options.resume.resumeToken;
  if (typeof rangeOptions.resumeToken === 'function') {
    return rangeOptions.resumeToken(url, options);
  }
  if (typeof rangeOptions.resumeToken === 'string') return rangeOptions.resumeToken;
  return options.attachmentId ?? options.storageId ?? url;
}

function createDownloadResumeState(
  options: MediaAttachmentTransferOptions,
  offsetBytes: number,
  resumeToken: string
): MediaAttachmentResumeState {
  return {
    operation: 'download',
    offsetBytes,
    resumeToken,
    updatedAt: Date.now(),
    expiresAt: options.resume?.expiresAt,
  };
}

function emitDownloadTransferProgress(
  options: MediaAttachmentTransferOptions,
  bytesTransferred: number,
  totalBytes: number | undefined,
  resumeToken: string | undefined,
  complete = false
): void {
  emitProgress(options.onProgress, {
    operation: 'download',
    phase: 'transfer',
    attempt: options.attempt,
    storageId: options.storageId,
    bytesTransferred,
    totalBytes,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'download',
    phase: complete ? 'complete' : 'transfer',
    attempt: options.attempt,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred,
    totalBytes,
    resumeToken,
  });
}

function handleDownloadHttpFailure(response: Response): never {
  if (response.status === 404) {
    throw new MediaAttachmentError(
      'Media attachment blob not found',
      MediaAttachmentErrorCode.BlobNotFound,
      { status: response.status }
    );
  }
  if (response.status === 416) {
    throwInvalidResumeState('Byte-range media download resume offset is invalid', response.status);
  }
  throw new MediaAttachmentError(
    `Media attachment download failed: ${response.status} ${response.statusText}`,
    MediaAttachmentErrorCode.DownloadFailed,
    { status: response.status }
  );
}

async function loadByteRangePrefix(
  resume: MediaAttachmentResumeState | undefined,
  partialStore: ByteRangeMediaAttachmentPartialStore | undefined
): Promise<Uint8Array> {
  if (!resume || (resume.offsetBytes ?? 0) === 0) {
    return new Uint8Array();
  }
  if (resume.operation !== 'download') {
    throwInvalidResumeState('Byte-range media download received non-download resume state');
  }
  if (!partialStore) {
    throwInvalidResumeState('Byte-range media download resume requires a partial-byte store');
  }

  const prefix = await partialStore.load(resume);
  if (!prefix || prefix.length !== resume.offsetBytes) {
    await clearByteRangePrefixes(partialStore, [resume]);
    throwInvalidResumeState('Byte-range media download partial state is missing or truncated');
  }
  return prefix;
}

async function persistByteRangePrefix(
  partialStore: ByteRangeMediaAttachmentPartialStore | undefined,
  options: MediaAttachmentTransferOptions,
  bytes: Uint8Array,
  resumeToken: string
): Promise<MediaAttachmentResumeState | undefined> {
  if (!partialStore) return undefined;
  const resume = createDownloadResumeState(options, bytes.length, resumeToken);
  await partialStore.save(resume, bytes);
  return resume;
}

function dedupeByteRangeResumeStates(
  resumes: ReadonlyArray<MediaAttachmentResumeState | undefined>
): MediaAttachmentResumeState[] {
  const seen = new Set<string>();
  const deduped: MediaAttachmentResumeState[] = [];

  for (const resume of resumes) {
    if (!resume) continue;
    const key = `${resume.operation}:${resume.resumeToken ?? ''}:${resume.offsetBytes ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(resume);
  }

  return deduped;
}

async function clearByteRangePrefixes(
  partialStore: ByteRangeMediaAttachmentPartialStore | undefined,
  resumes: ReadonlyArray<MediaAttachmentResumeState | undefined>
): Promise<void> {
  if (!partialStore?.clear) return;

  for (const resume of dedupeByteRangeResumeStates(resumes)) {
    try {
      await partialStore.clear(resume);
    } catch {
      // Cleanup failures must not mask transfer integrity decisions. App-level
      // orphan cleanup can remove stale encrypted partials on a later pass.
    }
  }
}

async function clearCurrentByteRangePrefix(
  partialStore: ByteRangeMediaAttachmentPartialStore | undefined,
  options: MediaAttachmentTransferOptions,
  offsetBytes: number,
  resumeToken: string
): Promise<void> {
  if (offsetBytes === 0 && !options.resume?.resumeToken) {
    return;
  }

  await clearByteRangePrefixes(partialStore, [
    createDownloadResumeState(options, offsetBytes, resumeToken),
  ]);
}

export function createByteRangeMediaAttachmentTransfer(
  rangeOptions: ByteRangeMediaAttachmentTransferOptions = {}
): MediaAttachmentTransfer {
  return {
    async download(url: string, options: MediaAttachmentTransferOptions = {}): Promise<Uint8Array> {
      assertNotAborted(options.signal);
      const fetchImpl = getFetchImplementation(rangeOptions.fetch, 'download');
      const resumeToken = resolveByteRangeResumeToken(url, options, rangeOptions);
      let bytes = await loadByteRangePrefix(options.resume, rangeOptions.partialStore);
      let offset = bytes.length;
      let totalBytes = options.totalBytes;
      const persistedPrefixes: MediaAttachmentResumeState[] = [];

      emitDownloadTransferProgress(options, offset, totalBytes, resumeToken);

      if (totalBytes !== undefined && offset >= totalBytes) {
        emitDownloadTransferProgress(options, offset, totalBytes, resumeToken, true);
        await clearByteRangePrefixes(rangeOptions.partialStore, [options.resume]);
        return bytes;
      }

      while (totalBytes === undefined || offset < totalBytes) {
        assertNotAborted(options.signal);
        const requestedRangeEnd =
          rangeOptions.chunkSizeBytes !== undefined
            ? offset + Math.max(1, rangeOptions.chunkSizeBytes) - 1
            : undefined;
        const rangeEnd =
          totalBytes !== undefined
            ? Math.min(requestedRangeEnd ?? totalBytes - 1, totalBytes - 1)
            : requestedRangeEnd;
        const shouldRequestRange = offset > 0 || rangeOptions.chunkSizeBytes !== undefined;
        const response = await fetchImpl(url, {
          method: 'GET',
          signal: options.signal,
          headers: {
            ...options.headers,
            ...(shouldRequestRange
              ? {
                  Range: `bytes=${offset}-${rangeEnd !== undefined ? rangeEnd : ''}`,
                }
              : {}),
          },
        });
        assertNotAborted(options.signal);

        if (!response.ok) {
          if (response.status === 416) {
            await clearCurrentByteRangePrefix(
              rangeOptions.partialStore,
              options,
              offset,
              resumeToken
            );
          }
          handleDownloadHttpFailure(response);
        }

        let rangedResponse = false;
        let responseContentRange: ParsedContentRange | null = null;
        if (shouldRequestRange) {
          if (response.status === 206) {
            rangedResponse = true;
            responseContentRange = parseContentRange(getHeader(response, 'content-range'));
            if (
              !responseContentRange ||
              responseContentRange.start !== offset ||
              (rangeEnd !== undefined && responseContentRange.end > rangeEnd)
            ) {
              await clearCurrentByteRangePrefix(
                rangeOptions.partialStore,
                options,
                offset,
                resumeToken
              );
              throwInvalidResumeState('Byte-range media download returned an unexpected range');
            }
            try {
              assertContentRangeTotalMatchesExpected(responseContentRange, totalBytes);
            } catch (error) {
              await clearCurrentByteRangePrefix(
                rangeOptions.partialStore,
                options,
                offset,
                resumeToken
              );
              throw error;
            }
            totalBytes = totalBytes ?? responseContentRange.totalBytes;
          } else if (response.status === 200 && offset > 0) {
            await clearCurrentByteRangePrefix(
              rangeOptions.partialStore,
              options,
              offset,
              resumeToken
            );
            throwInvalidResumeState('Byte-range media download server ignored resume offset');
          } else if (response.status !== 200) {
            handleDownloadHttpFailure(response);
          }
        }

        totalBytes = totalBytes ?? parseContentLength(response);
        const chunk = await readResponseBodyBytes(response, options.signal);
        if (responseContentRange) {
          try {
            assertContentRangeBodyLength(responseContentRange, chunk);
          } catch (error) {
            await clearCurrentByteRangePrefix(
              rangeOptions.partialStore,
              options,
              offset,
              resumeToken
            );
            throw error;
          }
        }
        assertCiphertextSizeWithinExpected(totalBytes, offset + chunk.length);
        if (chunk.length === 0 && (totalBytes === undefined || offset < totalBytes)) {
          throw new MediaAttachmentError(
            'Media attachment download returned an empty partial response',
            MediaAttachmentErrorCode.DownloadFailed,
            { status: response.status }
          );
        }

        bytes = offset === 0 && !rangedResponse ? chunk : concatBytes(bytes, chunk);
        offset = bytes.length;
        const persistedPrefix = await persistByteRangePrefix(
          rangeOptions.partialStore,
          options,
          bytes,
          resumeToken
        );
        if (persistedPrefix) {
          persistedPrefixes.push(persistedPrefix);
        }
        emitDownloadTransferProgress(
          options,
          offset,
          totalBytes,
          resumeToken,
          totalBytes !== undefined && offset >= totalBytes
        );

        if (!rangedResponse || rangeOptions.chunkSizeBytes === undefined) {
          break;
        }
      }

      if (totalBytes !== undefined && bytes.length !== totalBytes) {
        await clearByteRangePrefixes(rangeOptions.partialStore, [
          options.resume,
          ...persistedPrefixes,
        ]);
        throw new MediaAttachmentError(
          `Media attachment download size mismatch: expected ${totalBytes} bytes, received ${bytes.length}`,
          MediaAttachmentErrorCode.DownloadFailed
        );
      }

      await clearByteRangePrefixes(rangeOptions.partialStore, [
        options.resume,
        ...persistedPrefixes,
      ]);
      return bytes;
    },
  };
}

async function readResponseBytes(
  response: Response,
  options: MediaAttachmentTransferOptions
): Promise<Uint8Array> {
  const totalBytesHeader = getHeader(response, 'content-length');
  const headerBytes =
    totalBytesHeader && /^\d+$/.test(totalBytesHeader) ? Number(totalBytesHeader) : undefined;
  assertCiphertextSizeEqualsExpected(options.totalBytes, headerBytes);
  const totalBytes =
    options.totalBytes ?? (headerBytes !== undefined ? Number(headerBytes) : undefined);

  emitProgress(options.onProgress, {
    operation: 'download',
    phase: 'transfer',
    attempt: options.attempt,
    storageId: options.storageId,
    bytesTransferred: 0,
    totalBytes,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'download',
    phase: 'transfer',
    attempt: options.attempt,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred: 0,
    totalBytes,
    resumeToken: options.resume?.resumeToken,
  });

  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytesTransferred = 0;

    while (true) {
      assertNotAborted(options.signal);
      const { done, value } = await reader.read();
      if (done) break;
      const nextBytesTransferred = bytesTransferred + value.length;
      assertCiphertextSizeWithinExpected(options.totalBytes, nextBytesTransferred);
      chunks.push(value);
      bytesTransferred = nextBytesTransferred;
      emitProgress(options.onProgress, {
        operation: 'download',
        phase: 'transfer',
        attempt: options.attempt,
        storageId: options.storageId,
        bytesTransferred,
        totalBytes,
      });
      emitCheckpoint(options.onCheckpoint, {
        operation: 'download',
        phase: 'transfer',
        attempt: options.attempt,
        storageId: options.storageId,
        attachmentId: options.attachmentId,
        bytesTransferred,
        totalBytes,
        resumeToken: options.resume?.resumeToken,
      });
    }

    const data = concatBytes(...chunks);
    emitCheckpoint(options.onCheckpoint, {
      operation: 'download',
      phase: 'complete',
      attempt: options.attempt,
      storageId: options.storageId,
      attachmentId: options.attachmentId,
      bytesTransferred: data.length,
      totalBytes: totalBytes ?? data.length,
      resumeToken: options.resume?.resumeToken,
    });
    return data;
  }

  const data = new Uint8Array(await response.arrayBuffer());
  assertNotAborted(options.signal);
  assertCiphertextSizeEqualsExpected(options.totalBytes, data.length);
  emitProgress(options.onProgress, {
    operation: 'download',
    phase: 'transfer',
    attempt: options.attempt,
    storageId: options.storageId,
    bytesTransferred: data.length,
    totalBytes: totalBytes ?? data.length,
  });
  emitCheckpoint(options.onCheckpoint, {
    operation: 'download',
    phase: 'complete',
    attempt: options.attempt,
    storageId: options.storageId,
    attachmentId: options.attachmentId,
    bytesTransferred: data.length,
    totalBytes: totalBytes ?? data.length,
    resumeToken: options.resume?.resumeToken,
  });
  return data;
}

async function defaultDownload(
  url: string,
  options: MediaAttachmentTransferOptions = {}
): Promise<Uint8Array> {
  assertNotAborted(options.signal);
  if (typeof globalThis.fetch !== 'function') {
    throw new MediaAttachmentError(
      'Cannot download media attachment: fetch is not available',
      MediaAttachmentErrorCode.DownloadFailed
    );
  }

  const response = await globalThis.fetch(url, {
    signal: options.signal,
    headers: options.headers,
  });
  assertNotAborted(options.signal);
  if (!response.ok) {
    if (response.status === 404) {
      throw new MediaAttachmentError(
        'Media attachment blob not found',
        MediaAttachmentErrorCode.BlobNotFound,
        { status: response.status }
      );
    }
    throw new MediaAttachmentError(
      `Media attachment download failed: ${response.status} ${response.statusText}`,
      MediaAttachmentErrorCode.DownloadFailed,
      { status: response.status }
    );
  }

  return readResponseBytes(response, options);
}

const DEFAULT_MEDIA_RETRY_OPTIONS: Required<MediaAttachmentRetryOptions> = {
  maxRetries: 2,
  baseDelayMs: 250,
  maxDelayMs: 2_000,
  enableJitter: true,
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function resolveUploadRetryOptions(
  input: MediaAttachmentRetryOptions | undefined
): Required<MediaAttachmentRetryOptions> {
  return {
    ...DEFAULT_MEDIA_RETRY_OPTIONS,
    ...input,
  };
}

function calculateUploadRetryDelay(
  attempt: number,
  options: Required<MediaAttachmentRetryOptions>
): number {
  let delay = Math.min(options.baseDelayMs * Math.pow(2, attempt), options.maxDelayMs);
  if (options.enableJitter && delay > 0) {
    delay -= Math.random() * delay * 0.25;
  }
  return Math.floor(delay);
}

function isRetryableUploadStatus(status: number | undefined): boolean {
  if (status === undefined) return true;
  if (status === 403) return true;
  if (status === 408 || status === 409 || status === 425 || status === 429) return true;
  return status >= 500;
}

function isRetryableUploadError(error: unknown): boolean {
  if (error instanceof MediaAttachmentError) {
    if (error.code === MediaAttachmentErrorCode.ResumeStateInvalid) {
      return true;
    }
    return (
      error.code === MediaAttachmentErrorCode.UploadFailed && isRetryableUploadStatus(error.status)
    );
  }
  return true;
}

function isRetryableDownloadStatus(status: number | undefined): boolean {
  if (status === undefined) return true;
  if (status === 403) return true;
  if (status === 408 || status === 409 || status === 425 || status === 429) return true;
  return status >= 500;
}

function isRetryableDownloadError(error: unknown): boolean {
  if (error instanceof MediaAttachmentError) {
    if (error.code === MediaAttachmentErrorCode.BlobNotFound) {
      return false;
    }
    if (error.code === MediaAttachmentErrorCode.ResumeStateInvalid) {
      return true;
    }
    return (
      error.code === MediaAttachmentErrorCode.DownloadFailed &&
      isRetryableDownloadStatus(error.status)
    );
  }
  return true;
}

function normalizeDownloadError(error: unknown): unknown {
  if (error instanceof MediaAttachmentError) {
    if (error.status === 404 && error.code === MediaAttachmentErrorCode.DownloadFailed) {
      return new MediaAttachmentError(
        'Media attachment blob not found',
        MediaAttachmentErrorCode.BlobNotFound,
        { cause: error, status: 404 }
      );
    }
    return error;
  }

  const message = error instanceof Error ? error.message.toLowerCase() : '';
  if (
    message.includes('blob not found') ||
    message.includes('attachment blob not found') ||
    message.includes('media attachment not found')
  ) {
    return new MediaAttachmentError(
      'Media attachment blob not found',
      MediaAttachmentErrorCode.BlobNotFound,
      { cause: error }
    );
  }

  return error;
}

function getRetryStatus(error: unknown): number | undefined {
  return error instanceof MediaAttachmentError ? error.status : undefined;
}

function getRetryReason(
  error: unknown
): 'expired-url' | 'invalid-resume' | 'retryable-status' | 'transient-failure' {
  if (
    error instanceof MediaAttachmentError &&
    error.code === MediaAttachmentErrorCode.ResumeStateInvalid
  ) {
    return 'invalid-resume';
  }
  const status = getRetryStatus(error);
  if (status === 403) return 'expired-url';
  if (status !== undefined) return 'retryable-status';
  return 'transient-failure';
}

async function uploadCiphertextWithRetry(input: {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
  ciphertext: Uint8Array;
  requestId: string;
}): Promise<string> {
  const retry = resolveUploadRetryOptions(input.retry);
  let lastError: unknown;
  let resume = input.resume;
  let canonicalObjectId: string | undefined;
  const onCheckpoint = trackResumeCheckpoints(
    'upload',
    input.onCheckpoint,
    (nextResume) => {
      resume = nextResume;
    },
    () => resume
  );

  for (let attempt = 0; attempt <= retry.maxRetries; attempt++) {
    try {
      assertNotAborted(input.signal);
      emitProgress(input.onProgress, {
        operation: 'upload',
        phase: 'request-url',
        attempt,
        requestId: input.requestId,
      });
      emitCheckpoint(onCheckpoint, {
        operation: 'upload',
        phase: 'request-url',
        attempt,
        requestId: input.requestId,
        storageId: canonicalObjectId,
        bytesTransferred: resume?.offsetBytes ?? 0,
        totalBytes: input.ciphertext.length,
        resumeToken: resume?.resumeToken,
      });
      const { uploadUrl, objectId, headers, protocol } = await input.remoteObjectStore.createUpload(
        {
          requestId: input.requestId,
          contentType: 'application/octet-stream',
          contentLength: input.ciphertext.length,
        }
      );
      if (canonicalObjectId !== undefined && canonicalObjectId !== objectId) {
        throw new MediaAttachmentError(
          'Remote object storage returned a different object ID for an upload retry',
          MediaAttachmentErrorCode.UploadIdentityChanged
        );
      }
      canonicalObjectId = objectId;
      assertNotAborted(input.signal);
      const transfer =
        input.transfer ?? (protocol === 'tus' ? createTusMediaAttachmentTransfer() : undefined);
      const uploadHeaders = { ...headers };
      if (!Object.keys(uploadHeaders).some((name) => name.toLowerCase() === 'content-type')) {
        uploadHeaders['Content-Type'] = 'application/octet-stream';
      }
      const response = transfer?.upload
        ? await transfer.upload(uploadUrl, input.ciphertext, {
            headers: uploadHeaders,
            signal: input.signal,
            onProgress: input.onProgress,
            onCheckpoint,
            resume,
            attempt,
            totalBytes: input.ciphertext.length,
            requestId: input.requestId,
            storageId: objectId,
          })
        : await defaultUpload(uploadUrl, input.ciphertext, {
            headers: uploadHeaders,
            signal: input.signal,
            onProgress: input.onProgress,
            onCheckpoint,
            resume,
            attempt,
            totalBytes: input.ciphertext.length,
            requestId: input.requestId,
            storageId: objectId,
          });

      if (!response.ok) {
        throw new MediaAttachmentError(
          `Media attachment upload failed: ${response.status} ${response.statusText}`,
          MediaAttachmentErrorCode.UploadFailed,
          { status: response.status }
        );
      }

      await input.remoteObjectStore.completeUpload?.({ objectId });
      return objectId;
    } catch (error) {
      if (input.signal?.aborted) {
        throw new MediaAttachmentError(
          'Media attachment operation cancelled',
          MediaAttachmentErrorCode.Cancelled,
          { cause: input.signal.reason }
        );
      }
      lastError = error;
      const shouldClearResume =
        error instanceof MediaAttachmentError &&
        error.code === MediaAttachmentErrorCode.ResumeStateInvalid;
      if (shouldClearResume) {
        resume = undefined;
      }
      if (attempt >= retry.maxRetries || !isRetryableUploadError(error)) {
        break;
      }

      const delay = calculateUploadRetryDelay(attempt, retry);
      emitProgress(input.onProgress, {
        operation: 'upload',
        phase: 'retry',
        attempt,
        requestId: input.requestId,
        storageId: canonicalObjectId,
        status: getRetryStatus(error),
        retryInMs: delay,
        reason: getRetryReason(error),
      });
      emitCheckpoint(onCheckpoint, {
        operation: 'upload',
        phase: 'retry',
        attempt,
        requestId: input.requestId,
        storageId: canonicalObjectId,
        bytesTransferred: resume?.offsetBytes ?? 0,
        totalBytes: input.ciphertext.length,
        resumeToken: resume?.resumeToken,
      });
      if (delay > 0) {
        await sleep(delay);
      }
    }
  }

  if (lastError instanceof MediaAttachmentError) {
    throw lastError;
  }
  throw new MediaAttachmentError(
    'Media attachment upload failed',
    MediaAttachmentErrorCode.UploadFailed,
    { cause: lastError }
  );
}

async function downloadCiphertextWithRetry(input: {
  remoteObjectStore: SignalProtocolRemoteObjectStore;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
  storageId: string;
  attachmentId: string;
  expectedCiphertextSize: number;
}): Promise<Uint8Array> {
  const retry = resolveUploadRetryOptions(input.retry);
  let lastError: unknown;
  let resume = input.resume;
  const onCheckpoint = trackResumeCheckpoints(
    'download',
    input.onCheckpoint,
    (nextResume) => {
      resume = nextResume;
    },
    () => resume
  );

  for (let attempt = 0; attempt <= retry.maxRetries; attempt++) {
    try {
      assertNotAborted(input.signal);
      emitProgress(input.onProgress, {
        operation: 'download',
        phase: 'request-url',
        attempt,
        storageId: input.storageId,
      });
      emitCheckpoint(onCheckpoint, {
        operation: 'download',
        phase: 'request-url',
        attempt,
        storageId: input.storageId,
        attachmentId: input.attachmentId,
        bytesTransferred: resume?.offsetBytes ?? 0,
        totalBytes: input.expectedCiphertextSize,
        resumeToken: resume?.resumeToken,
      });
      const { downloadUrl, headers } = await input.remoteObjectStore.createDownload({
        objectId: input.storageId,
      });
      assertNotAborted(input.signal);
      return input.transfer?.download
        ? await input.transfer.download(downloadUrl, {
            headers,
            signal: input.signal,
            onProgress: input.onProgress,
            onCheckpoint,
            resume,
            attempt,
            totalBytes: input.expectedCiphertextSize,
            storageId: input.storageId,
            attachmentId: input.attachmentId,
          })
        : await defaultDownload(downloadUrl, {
            headers,
            signal: input.signal,
            onProgress: input.onProgress,
            onCheckpoint,
            resume,
            attempt,
            totalBytes: input.expectedCiphertextSize,
            storageId: input.storageId,
            attachmentId: input.attachmentId,
          });
    } catch (error) {
      if (input.signal?.aborted) {
        throw new MediaAttachmentError(
          'Media attachment operation cancelled',
          MediaAttachmentErrorCode.Cancelled,
          { cause: input.signal.reason }
        );
      }
      const normalizedError = normalizeDownloadError(error);
      lastError = normalizedError;
      const shouldClearResume =
        normalizedError instanceof MediaAttachmentError &&
        normalizedError.code === MediaAttachmentErrorCode.ResumeStateInvalid;
      if (shouldClearResume) {
        resume = undefined;
      }
      if (attempt >= retry.maxRetries || !isRetryableDownloadError(normalizedError)) {
        break;
      }

      const delay = calculateUploadRetryDelay(attempt, retry);
      emitProgress(input.onProgress, {
        operation: 'download',
        phase: 'retry',
        attempt,
        storageId: input.storageId,
        status: getRetryStatus(normalizedError),
        retryInMs: delay,
        reason: getRetryReason(normalizedError),
      });
      emitCheckpoint(onCheckpoint, {
        operation: 'download',
        phase: 'retry',
        attempt,
        storageId: input.storageId,
        attachmentId: input.attachmentId,
        bytesTransferred: resume?.offsetBytes ?? 0,
        totalBytes: input.expectedCiphertextSize,
        resumeToken: resume?.resumeToken,
      });
      if (delay > 0) {
        await sleep(delay);
      }
    }
  }

  if (lastError instanceof MediaAttachmentError) {
    throw lastError;
  }
  throw new MediaAttachmentError(
    'Media attachment download failed',
    MediaAttachmentErrorCode.DownloadFailed,
    { cause: lastError }
  );
}

function decodeAttachmentKey(key: string): Uint8Array {
  try {
    const keyBytes = base64ToBytes(toBase64(key));
    if (keyBytes.length !== 32) {
      throw new Error(`expected 32 bytes, received ${keyBytes.length}`);
    }
    return keyBytes;
  } catch (cause) {
    throw new MediaAttachmentError(
      'Invalid media attachment pointer: key must be a base64-encoded 32-byte key',
      MediaAttachmentErrorCode.InvalidPointer,
      { cause }
    );
  }
}

async function assertDigestMatches(ciphertext: Uint8Array, expectedDigest: string): Promise<void> {
  let expectedDigestBytes: Uint8Array;
  try {
    expectedDigestBytes = base64ToBytes(toBase64(expectedDigest));
  } catch (cause) {
    throw new MediaAttachmentError(
      'Invalid media attachment pointer: digest must be base64-encoded SHA-256',
      MediaAttachmentErrorCode.InvalidPointer,
      { cause }
    );
  }

  const actualDigestBytes = await sha256(ciphertext);
  if (
    expectedDigestBytes.length !== actualDigestBytes.length ||
    !constantTimeEqual(expectedDigestBytes, actualDigestBytes)
  ) {
    throw new MediaAttachmentError(
      'Media attachment digest mismatch',
      MediaAttachmentErrorCode.DigestMismatch
    );
  }
}

/**
 * Encrypt and upload media bytes, returning a SDK attachment pointer.
 *
 * The client computes the encrypted object digest and object ID once. Upload
 * retries request fresh presigned URLs for that same key. This handles expired
 * upload URLs without changing the pointer metadata that the client later
 * encrypts into the Signal Protocol message.
 */
export async function prepareMediaAttachmentUpload(
  data: Uint8Array,
  options: PrepareMediaAttachmentUploadOptions
): Promise<MediaAttachmentPointer> {
  assertNotAborted(options.signal);
  const contentType = options.contentType ?? 'application/octet-stream';
  const clientUuid = options.clientUuid ?? (await generateMediaAttachmentClientUuid());
  const requestId = options.requestId ?? (await generateMediaAttachmentUploadRequestId());
  assertString(requestId, 'requestId');
  assertNotAborted(options.signal);
  validateMediaAttachmentMetadata(
    {
      contentType,
      size: data.length,
      fileName: options.fileName,
      caption: options.caption,
      blurHash: options.blurHash,
      width: options.width,
      height: options.height,
      durationMs: options.durationMs,
      thumbnail: options.thumbnail,
      waveform: options.waveform,
      isViewOnce: options.isViewOnce,
      flags: options.flags,
      clientUuid,
      cdnNumber: options.cdnNumber,
    },
    options.policy
  );
  emitProgress(options.onProgress, {
    operation: 'upload',
    phase: 'encrypt',
    bytesTransferred: 0,
    totalBytes: data.length,
  });
  const masterKey = await generateRandomBytes(32);
  const masterKeyBase64 = bytesToBase64(masterKey);

  try {
    assertNotAborted(options.signal);
    const { ciphertext, segmentSize } = await streamingEncrypt(masterKey, data);
    assertNotAborted(options.signal);
    emitProgress(options.onProgress, {
      operation: 'upload',
      phase: 'encrypt',
      bytesTransferred: data.length,
      totalBytes: data.length,
    });
    const digest = bytesToBase64(await sha256(ciphertext));
    const storageId = await uploadCiphertextWithRetry({
      remoteObjectStore: options.remoteObjectStore,
      transfer: options.transfer,
      retry: options.retry,
      signal: options.signal,
      onProgress: options.onProgress,
      onCheckpoint: options.onCheckpoint,
      resume: options.resume,
      ciphertext,
      requestId,
    });

    const pointer = createMediaAttachmentPointer({
      storageId,
      key: masterKeyBase64,
      digest,
      segmentSize,
      ciphertextSize: ciphertext.length,
      contentType,
      size: data.length,
      uploadTimestamp: Date.now(),
      blurHash: options.blurHash,
      thumbnail: options.thumbnail,
      width: options.width,
      height: options.height,
      durationMs: options.durationMs,
      waveform: options.waveform,
      fileName: options.fileName,
      caption: options.caption,
      isViewOnce: options.isViewOnce,
      flags: options.flags,
      clientUuid,
      cdnNumber: options.cdnNumber,
    });
    validateMediaAttachmentMetadata(pointer, options.policy);
    emitProgress(options.onProgress, {
      operation: 'upload',
      phase: 'complete',
      storageId: pointer.storageId,
      bytesTransferred: ciphertext.length,
      totalBytes: ciphertext.length,
    });
    return pointer;
  } finally {
    secureZeroBytes(masterKey);
  }
}

/**
 * Download, verify, and decrypt a Signal Protocol media attachment pointer.
 *
 * This is the safe receive-side counterpart to attachment upload. It validates
 * pointer metadata, downloads opaque ciphertext from the object store, and
 * verifies length and SHA-256 digest before decryption. It then decrypts with
 * the package's streaming AEAD format.
 */
export async function resolveMediaAttachment(
  attachment: CreateMediaAttachmentPointerInput,
  options: ResolveMediaAttachmentOptions
): Promise<ResolvedMediaAttachment> {
  const pointer = validateMediaAttachmentPolicy(attachment, options.policy);
  const ciphertext = await downloadCiphertextWithRetry({
    remoteObjectStore: options.remoteObjectStore,
    transfer: options.transfer,
    retry: options.retry,
    signal: options.signal,
    onProgress: options.onProgress,
    onCheckpoint: options.onCheckpoint,
    resume: options.resume,
    storageId: pointer.storageId,
    attachmentId: createMediaAttachmentId(pointer),
    expectedCiphertextSize: pointer.ciphertextSize,
  });
  assertNotAborted(options.signal);

  if (ciphertext.length !== pointer.ciphertextSize) {
    throw new MediaAttachmentError(
      `Media attachment ciphertext size mismatch: expected ${pointer.ciphertextSize}, received ${ciphertext.length}`,
      MediaAttachmentErrorCode.CiphertextSizeMismatch
    );
  }

  emitProgress(options.onProgress, {
    operation: 'download',
    phase: 'verify',
    storageId: pointer.storageId,
    bytesTransferred: ciphertext.length,
    totalBytes: pointer.ciphertextSize,
  });
  await assertDigestMatches(ciphertext, pointer.digest);
  assertNotAborted(options.signal);

  const keyBytes = decodeAttachmentKey(pointer.key);
  try {
    emitProgress(options.onProgress, {
      operation: 'download',
      phase: 'decrypt',
      storageId: pointer.storageId,
      bytesTransferred: 0,
      totalBytes: pointer.size,
    });
    const data = await streamingDecrypt(keyBytes, ciphertext, new Uint8Array(0), {
      segmentSize: pointer.segmentSize,
    });
    assertNotAborted(options.signal);

    if (data.length !== pointer.size) {
      throw new MediaAttachmentError(
        `Media attachment plaintext size mismatch: expected ${pointer.size}, received ${data.length}`,
        MediaAttachmentErrorCode.PlaintextSizeMismatch
      );
    }

    emitProgress(options.onProgress, {
      operation: 'download',
      phase: 'decrypt',
      storageId: pointer.storageId,
      bytesTransferred: data.length,
      totalBytes: pointer.size,
    });
    emitProgress(options.onProgress, {
      operation: 'download',
      phase: 'complete',
      storageId: pointer.storageId,
      bytesTransferred: data.length,
      totalBytes: pointer.size,
    });

    return {
      data,
      attachment: pointer,
      contentType: pointer.contentType,
      size: pointer.size,
      fileName: pointer.fileName,
      caption: pointer.caption,
      width: pointer.width,
      height: pointer.height,
      blurHash: pointer.blurHash,
      thumbnail: pointer.thumbnail,
      durationMs: pointer.durationMs,
      waveform: pointer.waveform,
      isViewOnce: pointer.isViewOnce,
      flags: pointer.flags,
      storageId: pointer.storageId,
      digest: pointer.digest,
      ciphertextSize: pointer.ciphertextSize,
    };
  } catch (error) {
    if (error instanceof MediaAttachmentError) {
      throw error;
    }
    throw new MediaAttachmentError(
      'Media attachment decryption failed',
      MediaAttachmentErrorCode.DecryptionFailed,
      { cause: error }
    );
  } finally {
    secureZeroBytes(keyBytes);
  }
}

export async function deleteMediaAttachment(
  attachment: CreateMediaAttachmentPointerInput,
  options: DeleteMediaAttachmentOptions
): Promise<DeleteMediaAttachmentResult> {
  const pointer = createMediaAttachmentPointer(attachment);
  assertNotAborted(options.signal);
  if (!options.remoteObjectStore.deleteObject) {
    throw new MediaAttachmentError(
      'Media attachment remote delete is unavailable for the configured object store',
      MediaAttachmentErrorCode.DeleteUnavailable
    );
  }

  try {
    emitProgress(options.onProgress, {
      operation: 'delete',
      phase: 'delete',
      storageId: pointer.storageId,
    });
    await options.remoteObjectStore.deleteObject({
      objectId: pointer.storageId,
    });
    assertNotAborted(options.signal);
    emitProgress(options.onProgress, {
      operation: 'delete',
      phase: 'complete',
      storageId: pointer.storageId,
    });
    return {
      storageId: pointer.storageId,
      deletedRemoteObject: true,
    };
  } catch (cause) {
    if (options.signal?.aborted) {
      throw new MediaAttachmentError(
        'Media attachment operation cancelled',
        MediaAttachmentErrorCode.Cancelled,
        { cause: options.signal.reason }
      );
    }
    throw new MediaAttachmentError(
      'Media attachment remote delete failed',
      MediaAttachmentErrorCode.DeleteFailed,
      { cause }
    );
  }
}

export const downloadMediaAttachment = resolveMediaAttachment;
