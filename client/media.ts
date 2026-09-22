import type { SignalProtocolRemoteObjectStore } from "../remote/object-store";
import {
  isRemoteObjectUploadFailureCode,
  remoteObjectUploadFailure,
  RemoteObjectUploadError,
  type RemoteObjectUploadFailure,
  type RemoteObjectUploadFailureCode,
} from "../remote/object-store/upload-error";
import { matchesUploadReceipt } from "../remote/object-store/validation";
import { assertPreparedUploadByteLimit } from "./media-upload-budget";
import type { ISignalProtocolLocalStore } from "../types/api";
import {
  MediaQueuePersistence,
  MediaQueueConcurrentUpdateError,
} from "./media-queue-persistence";
import { bytesToBase64, sha256 } from "../internal/crypto";
import {
  createMediaAttachmentId,
  createMediaAttachmentPointer,
  executeMediaAttachmentJob,
  generateMediaAttachmentUploadRequestId,
  prepareMediaAttachmentUploadData,
  validateMediaAttachmentPolicy,
  MediaAttachmentError,
  MediaAttachmentErrorCode,
  MediaAttachmentJobExecutionStatus,
  MediaAttachmentJobOperation,
  MediaAttachmentJobPriority,
  MediaAttachmentJobSource,
  planMediaAttachmentCleanupJobs,
  planMediaAttachmentDownloadJob,
  planMediaAttachmentUploadJob,
  type ExecuteMediaAttachmentJobOptions,
  type MediaAttachmentBackgroundJob,
  type MediaAttachmentCheckpointCallback,
  type MediaAttachmentDeleteSyncInput,
  type MediaAttachmentJobExecutionResult,
  type MediaAttachmentJobPriority as MediaAttachmentJobPriorityType,
  type MediaAttachmentPointer,
  type MediaAttachmentPreparedUploadStore,
  type PreparedMediaAttachmentUpload,
  type MediaAttachmentPolicy,
  type MediaAttachmentProgressCallback,
  type MediaAttachmentRetryOptions,
  type MediaAttachmentTransfer,
  type PlanMediaAttachmentCleanupJobsInput,
  type PlanMediaAttachmentDownloadJobInput,
  type PlanMediaAttachmentUploadJobInput,
  type PrepareMediaAttachmentUploadOptions,
  type ResolvedMediaAttachment,
} from "../media";
import {
  preparedUploadFingerprint,
  preparedUploadCiphertextSize,
  samePreparedUploadIntent,
} from "../media/prepared-upload";

const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY = "signal:mediaQueue:v1";
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_JOBS_DEFAULT = 200;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT = 5;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_BASE_RETRY_DELAY_MS_DEFAULT = 30_000;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_RETRY_DELAY_MS_DEFAULT =
  60 * 60 * 1000;

interface StoredSignalProtocolClientMediaQueue {
  version: 1;
  jobs: MediaAttachmentBackgroundJob[];
  uploads?: Record<string, StoredSignalProtocolClientMediaUpload>;
  pointers?: Record<string, MediaAttachmentPointer>;
}

interface SignalProtocolClientMediaQueueState {
  jobs: MediaAttachmentBackgroundJob[];
  uploads: Map<string, StoredSignalProtocolClientMediaUpload>;
  pointers: Map<string, MediaAttachmentPointer>;
  activeJobId?: string;
}

interface StoredSignalProtocolClientMediaUpload {
  localMediaId: string;
  requestId: string;
  contentType: string;
  size: number;
  policy?: MediaAttachmentPolicy;
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
  preparedFingerprint?: string;
  preparationStarted?: true;
  preparedAt?: number;
  abandonment?: "requested" | "confirmed";
  remoteObjectId?: string;
  transferCompletedAt?: number;
  callbackDelivered?: boolean;
  failureCode?: RemoteObjectUploadFailureCode;
}

export interface SignalProtocolClientLoadLocalAttachmentInput extends Omit<
  StoredSignalProtocolClientMediaUpload,
  | "preparedFingerprint"
  | "preparationStarted"
  | "preparedAt"
  | "abandonment"
  | "remoteObjectId"
  | "transferCompletedAt"
  | "callbackDelivered"
  | "failureCode"
> {
  job: MediaAttachmentBackgroundJob;
}

export interface SignalProtocolClientLoadedLocalAttachment {
  data: Uint8Array;
  options?: Omit<PrepareMediaAttachmentUploadOptions, "remoteObjectStore">;
}

export interface SignalProtocolClientSaveUploadedAttachmentInput {
  job: MediaAttachmentBackgroundJob;
  localMediaId: string;
  attachment: MediaAttachmentPointer;
}

export interface SignalProtocolClientSaveDownloadedAttachmentInput {
  job: MediaAttachmentBackgroundJob;
  attachmentId: string;
  downloaded: ResolvedMediaAttachment;
}

export interface SignalProtocolClientDeleteLocalAttachmentInput {
  job: MediaAttachmentBackgroundJob;
  attachmentId: string;
  storageId?: string;
}

export interface SignalProtocolClientSyncDeleteInput {
  job: MediaAttachmentBackgroundJob;
  deleteSync: MediaAttachmentDeleteSyncInput;
}

export interface SignalProtocolClientMediaConfig {
  /** Required for upload execution. Persist exact ciphertext and private pointer material atomically. */
  preparedUploads?: MediaAttachmentPreparedUploadStore;
  /**
   * Required to queue uploads. Bound total ciphertext bytes for queued uploads.
   * Reserve each upload at enqueue, before loading its draft. Keep the reservation
   * through uncertain outcomes until the queue removes that upload after cleanup.
   *
   * Select this device-local budget in the application. No default applies.
   * Allow separate physical space for metadata, file commits, and encryption memory.
   */
  maxPreparedUploadBytes?: number;
  /**
   * Load app-owned local bytes for a queued upload.
   *
   * The Signal Protocol package owns encryption and upload execution. The app owns draft
   * files, cache paths, and file permissions, so bytes enter the queue through
   * this callback instead of hidden package storage.
   */
  loadLocalAttachment?: (
    input: SignalProtocolClientLoadLocalAttachmentInput,
  ) => Promise<Uint8Array | SignalProtocolClientLoadedLocalAttachment | null>;

  /**
   * Persist the encrypted attachment pointer produced by a queued upload.
   */
  saveUploadedAttachment?: (
    input: SignalProtocolClientSaveUploadedAttachmentInput,
  ) => Promise<void>;

  /**
   * Persist plaintext bytes returned by a queued download.
   */
  saveDownloadedAttachment?: (
    input: SignalProtocolClientSaveDownloadedAttachmentInput,
  ) => Promise<void>;

  /**
   * Delete app-owned local cache state for a cleanup job.
   */
  deleteLocalAttachment?: (
    input: SignalProtocolClientDeleteLocalAttachmentInput,
  ) => Promise<void>;

  /**
   * Optional linked-device cleanup sync sender.
   */
  syncDelete?: (input: SignalProtocolClientSyncDeleteInput) => Promise<void>;

  /**
   * Bound the queue kept in the Signal Protocol local store metadata.
   *
   * @default 200
   */
  maxJobs?: number;

  /**
   * Maximum automatic attempts. Uploads retain their identity after this limit.
   *
   * @default 5
   */
  maxAttempts?: number;

  /**
   * First retry delay for transient job failures.
   *
   * @default 30000
   */
  baseRetryDelayMs?: number;

  /**
   * Maximum retry delay for transient job failures.
   *
   * @default 3600000
   */
  maxRetryDelayMs?: number;
}

export interface SignalProtocolClientMediaOperationOptions {
  now?: number;
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  policy?: MediaAttachmentPolicy;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
}

export interface SignalProtocolClientProcessPendingMediaOptions extends SignalProtocolClientMediaOperationOptions {
  limit?: number;
}

export interface SignalProtocolClientMediaProcessResult {
  attempted: number;
  abandoned: number;
  completed: number;
  skipped: number;
  failed: number;
  expired: number;
  /** Broker refusals that require explicit recovery with the original preparation. */
  uploadFailures: Array<{ jobId: string; failure: RemoteObjectUploadFailure }>;
  results: MediaAttachmentJobExecutionResult[];
}

interface StorageBackedSignalProtocolClientMediaOptions {
  storage: ISignalProtocolLocalStore;
  remoteObjectStore?: SignalProtocolRemoteObjectStore;
  config?: SignalProtocolClientMediaConfig;
}

export type SignalProtocolClientMediaUploadInput =
  PlanMediaAttachmentUploadJobInput;
export type SignalProtocolClientMediaDownloadInput =
  PlanMediaAttachmentDownloadJobInput;
export type SignalProtocolClientMediaCleanupInput =
  PlanMediaAttachmentCleanupJobsInput;

export interface SignalProtocolClientMediaCompletedResult {
  status: "completed";
  jobId: string;
  execution: MediaAttachmentJobExecutionResult;
}

export interface SignalProtocolClientMediaPendingResult {
  status: "pending";
  jobId: string;
}

export interface SignalProtocolClientMediaSkippedResult {
  status: "skipped";
  jobId: string;
  execution: MediaAttachmentJobExecutionResult;
}

export interface SignalProtocolClientMediaFailedResult {
  status: "failed";
  jobId: string;
  failure?: RemoteObjectUploadFailure;
}

export type SignalProtocolClientMediaOperationResult =
  | SignalProtocolClientMediaCompletedResult
  | SignalProtocolClientMediaPendingResult
  | SignalProtocolClientMediaSkippedResult
  | SignalProtocolClientMediaFailedResult;

export interface SignalProtocolClientMediaUploadCompletedResult {
  status: "completed";
  jobId: string;
  attachment: MediaAttachmentPointer;
  execution: MediaAttachmentJobExecutionResult;
}

export type SignalProtocolClientMediaUploadResult =
  | SignalProtocolClientMediaUploadCompletedResult
  | SignalProtocolClientMediaPendingResult
  | SignalProtocolClientMediaSkippedResult
  | SignalProtocolClientMediaFailedResult;

export interface SignalProtocolClientMediaDownloadNotNeededResult {
  status: "skipped";
  reason: "not-needed";
  attachmentId: string;
}

export interface SignalProtocolClientMediaDownloadCompletedResult {
  status: "completed";
  jobId: string;
  attachmentId: string;
  downloaded: ResolvedMediaAttachment;
  execution: MediaAttachmentJobExecutionResult;
}

export type SignalProtocolClientMediaDownloadResult =
  | SignalProtocolClientMediaDownloadNotNeededResult
  | SignalProtocolClientMediaDownloadCompletedResult
  | SignalProtocolClientMediaPendingResult
  | SignalProtocolClientMediaSkippedResult
  | SignalProtocolClientMediaFailedResult;

export type SignalProtocolClientMediaCleanupResult =
  | {
      status: "completed";
      jobs: SignalProtocolClientMediaOperationResult[];
    }
  | {
      status: "pending";
      jobs: SignalProtocolClientMediaOperationResult[];
    };

export interface SignalProtocolClientMedia {
  abandonUpload(
    jobId: string,
  ): Promise<SignalProtocolClientMediaAbandonmentResult>;

  upload(
    input: SignalProtocolClientMediaUploadInput,
    options?: SignalProtocolClientMediaOperationOptions,
  ): Promise<SignalProtocolClientMediaUploadResult>;

  download(
    input: SignalProtocolClientMediaDownloadInput,
    options?: SignalProtocolClientMediaOperationOptions,
  ): Promise<SignalProtocolClientMediaDownloadResult>;

  cleanup(
    input: SignalProtocolClientMediaCleanupInput,
    options?: SignalProtocolClientMediaOperationOptions,
  ): Promise<SignalProtocolClientMediaCleanupResult>;

  processPending(
    options?: SignalProtocolClientProcessPendingMediaOptions,
  ): Promise<SignalProtocolClientMediaProcessResult>;
}

export type SignalProtocolClientMediaAbandonmentResult =
  | {
      status: "abandoned" | "pending" | "not-found";
      jobId: string;
    }
  | {
      status: "completed";
      jobId: string;
      attachment: MediaAttachmentPointer;
    };

const localOnlyObjectStore: SignalProtocolRemoteObjectStore = {
  async createUpload() {
    throw new Error(
      "Signal Protocol media operation requires remoteObjectStore for upload",
    );
  },
  async createDownload() {
    throw new Error(
      "Signal Protocol media operation requires remoteObjectStore for download",
    );
  },
  async deleteObject() {
    throw new Error(
      "Signal Protocol media operation requires remoteObjectStore for remote delete",
    );
  },
};

function priorityRank(priority: MediaAttachmentJobPriorityType): number {
  switch (priority) {
    case MediaAttachmentJobPriority.High:
      return 3;
    case MediaAttachmentJobPriority.Normal:
      return 2;
    case MediaAttachmentJobPriority.Low:
      return 1;
  }
}

function compareMediaAttachmentJobs(
  left: MediaAttachmentBackgroundJob,
  right: MediaAttachmentBackgroundJob,
): number {
  const priorityDelta =
    priorityRank(right.priority) - priorityRank(left.priority);
  if (priorityDelta !== 0) {
    return priorityDelta;
  }

  return (
    left.notBefore - right.notBefore ||
    left.createdAt - right.createdAt ||
    left.jobId.localeCompare(right.jobId)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isInteger(value: unknown): value is number {
  return Number.isSafeInteger(value);
}

function isMediaAttachmentJob(
  value: unknown,
): value is MediaAttachmentBackgroundJob {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.jobId === "string" &&
    Object.values(MediaAttachmentJobOperation).includes(
      value.operation as never,
    ) &&
    Object.values(MediaAttachmentJobSource).includes(value.source as never) &&
    Object.values(MediaAttachmentJobPriority).includes(
      value.priority as never,
    ) &&
    typeof value.requiresNetwork === "boolean" &&
    typeof value.attachmentId === "string" &&
    isInteger(value.attempt) &&
    isInteger(value.createdAt) &&
    isInteger(value.notBefore) &&
    (value.storageId === undefined || typeof value.storageId === "string") &&
    (value.deliveryId === undefined || typeof value.deliveryId === "string") &&
    (value.reason === undefined || typeof value.reason === "string")
  );
}

function normalizePointer(value: unknown): MediaAttachmentPointer | null {
  try {
    return createMediaAttachmentPointer(value as never);
  } catch {
    return null;
  }
}

function isStoredUpload(
  value: unknown,
): value is StoredSignalProtocolClientMediaUpload {
  return (
    isRecord(value) &&
    typeof value.localMediaId === "string" &&
    value.localMediaId.length > 0 &&
    typeof value.requestId === "string" &&
    value.requestId.length > 0 &&
    typeof value.contentType === "string" &&
    value.contentType.length > 0 &&
    isInteger(value.size) &&
    value.size >= 0 &&
    (value.preparedFingerprint === undefined ||
      typeof value.preparedFingerprint === "string") &&
    (value.preparationStarted === undefined ||
      value.preparationStarted === true) &&
    (value.preparedAt === undefined ||
      (isInteger(value.preparedAt) && value.preparedAt > 0)) &&
    (value.abandonment === undefined ||
      value.abandonment === "requested" ||
      value.abandonment === "confirmed") &&
    (value.remoteObjectId === undefined ||
      (typeof value.remoteObjectId === "string" &&
        value.remoteObjectId.length > 0)) &&
    (value.transferCompletedAt === undefined ||
      (isInteger(value.transferCompletedAt) &&
        value.transferCompletedAt >= 0)) &&
    (value.callbackDelivered === undefined ||
      typeof value.callbackDelivered === "boolean") &&
    (value.failureCode === undefined ||
      isRemoteObjectUploadFailureCode(value.failureCode))
  );
}

function mergeJob(
  existing: MediaAttachmentBackgroundJob,
  incoming: MediaAttachmentBackgroundJob,
): MediaAttachmentBackgroundJob {
  if (priorityRank(incoming.priority) <= priorityRank(existing.priority)) {
    return {
      ...existing,
      resume: incoming.resume ?? existing.resume,
      notBefore: Math.min(existing.notBefore, incoming.notBefore),
    };
  }

  return {
    ...existing,
    source: incoming.source,
    priority: incoming.priority,
    requiresNetwork: incoming.requiresNetwork,
    attempt: Math.max(existing.attempt, incoming.attempt),
    notBefore: Math.min(existing.notBefore, incoming.notBefore),
    resume: incoming.resume ?? existing.resume,
  };
}

function normalizeJobs(
  jobs: readonly MediaAttachmentBackgroundJob[],
  maxJobs: number,
): MediaAttachmentBackgroundJob[] {
  const deduped = new Map<string, MediaAttachmentBackgroundJob>();

  for (const job of jobs) {
    if (!isMediaAttachmentJob(job)) {
      throw new Error(
        "The saved media queue contains an invalid job. Restore the local queue before retrying.",
      );
    }

    const existing = deduped.get(job.jobId);
    deduped.set(job.jobId, existing ? mergeJob(existing, job) : job);
  }

  if (deduped.size > maxJobs)
    throw new Error(
      "The media queue is full. Complete existing jobs before adding work.",
    );
  return [...deduped.values()].sort(compareMediaAttachmentJobs);
}

function nextRetryTimestamp(
  job: MediaAttachmentBackgroundJob,
  now: number,
  config?: SignalProtocolClientMediaConfig,
): number {
  const baseDelay =
    config?.baseRetryDelayMs ??
    SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_BASE_RETRY_DELAY_MS_DEFAULT;
  const maxDelay =
    config?.maxRetryDelayMs ??
    SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_RETRY_DELAY_MS_DEFAULT;
  const delay = Math.min(maxDelay, baseDelay * 2 ** Math.max(0, job.attempt));
  return now + delay;
}

function normalizeLoadedLocalAttachment(
  value: Uint8Array | SignalProtocolClientLoadedLocalAttachment | null,
): SignalProtocolClientLoadedLocalAttachment | null {
  if (!value) {
    return null;
  }

  return value instanceof Uint8Array ? { data: value } : value;
}

function uploadOptionsFromStoredUpload(
  upload: StoredSignalProtocolClientMediaUpload,
): Omit<PrepareMediaAttachmentUploadOptions, "remoteObjectStore"> {
  return {
    requestId: upload.requestId,
    contentType: upload.contentType,
    policy: upload.policy,
    fileName: upload.fileName,
    caption: upload.caption,
    blurHash: upload.blurHash,
    width: upload.width,
    height: upload.height,
    durationMs: upload.durationMs,
    thumbnail: upload.thumbnail,
    waveform: upload.waveform,
    isViewOnce: upload.isViewOnce,
    flags: upload.flags,
    clientUuid: upload.clientUuid,
    cdnNumber: upload.cdnNumber,
  };
}

function preparedUploadMatchesQueue(
  upload: StoredSignalProtocolClientMediaUpload,
  prepared: PreparedMediaAttachmentUpload,
): boolean {
  if (
    prepared.requestId !== upload.requestId ||
    prepared.pointer.size !== upload.size ||
    prepared.ciphertext.byteLength !==
      preparedUploadCiphertextSize(upload.size) ||
    prepared.pointer.ciphertextSize !== prepared.ciphertext.byteLength
  )
    return false;
  const pointer = prepared.pointer as unknown as Record<string, unknown>;
  return Object.entries(uploadOptionsFromStoredUpload(upload)).every(
    ([key, value]) => {
      if (
        key === "requestId" ||
        key === "policy" ||
        (key === "clientUuid" && value === undefined)
      )
        return true;
      return JSON.stringify(pointer[key]) === JSON.stringify(value);
    },
  );
}

/** @internal */
export class StorageBackedSignalProtocolClientMedia implements SignalProtocolClientMedia {
  private readonly storage: ISignalProtocolLocalStore;
  private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore;
  private readonly config?: SignalProtocolClientMediaConfig;
  private storeLock: Promise<void> = Promise.resolve();
  private readonly queuePersistence: MediaQueuePersistence;

  constructor(options: StorageBackedSignalProtocolClientMediaOptions) {
    this.storage = options.storage;
    this.queuePersistence = new MediaQueuePersistence(
      options.storage,
      SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY,
    );
    this.remoteObjectStore = options.remoteObjectStore;
    this.config = options.config;
  }

  async upload(
    input: SignalProtocolClientMediaUploadInput,
    options: SignalProtocolClientMediaOperationOptions = {},
  ): Promise<SignalProtocolClientMediaUploadResult> {
    const job = await this.enqueueUploadJob(input);
    const result = await this.processJob(job.jobId, options);
    if (result.status === "completed" && result.execution.uploadedAttachment) {
      return {
        status: "completed",
        jobId: job.jobId,
        attachment: result.execution.uploadedAttachment,
        execution: result.execution,
      };
    }
    if (result.status === "completed") {
      return { status: "failed", jobId: job.jobId };
    }
    return result;
  }

  async download(
    input: SignalProtocolClientMediaDownloadInput,
    options: SignalProtocolClientMediaOperationOptions = {},
  ): Promise<SignalProtocolClientMediaDownloadResult> {
    const job = await this.enqueueDownloadJob(input);
    if (!job) {
      const attachment = createMediaAttachmentPointer(input.attachment);
      return {
        status: "skipped",
        reason: "not-needed",
        attachmentId: createMediaAttachmentId(attachment),
      };
    }

    const result = await this.processJob(job.jobId, options);
    if (
      result.status === "completed" &&
      result.execution.downloadedAttachment
    ) {
      return {
        status: "completed",
        jobId: job.jobId,
        attachmentId: job.attachmentId,
        downloaded: result.execution.downloadedAttachment,
        execution: result.execution,
      };
    }
    if (result.status === "completed") {
      return { status: "failed", jobId: job.jobId };
    }
    return result;
  }

  async abandonUpload(
    jobId: string,
  ): Promise<SignalProtocolClientMediaAbandonmentResult> {
    return this.withStoreLock(() => this.abandonUploadLocked(jobId));
  }

  private async abandonUploadLocked(
    jobId: string,
  ): Promise<SignalProtocolClientMediaAbandonmentResult> {
    const artifacts = this.config?.preparedUploads;
    if (!artifacts)
      throw new Error(
        "Configure media.preparedUploads before abandoning a queued upload.",
      );
    const cancellation = await artifacts.withExclusiveAccess(async () => {
      const state = await this.loadState();
      const job = state.jobs.find((item) => item.jobId === jobId);
      if (!job) return undefined;
      const upload = state.uploads.get(jobId);
      if (job.operation !== MediaAttachmentJobOperation.Upload || !upload)
        throw new Error("Only a queued upload can be abandoned.");
      const completed = state.pointers.get(jobId);
      if (completed) return { completed };
      state.activeJobId = jobId;
      upload.abandonment ??= "requested";
      delete upload.failureCode;
      await this.saveState(state);
      if (upload.preparationStarted && upload.preparedAt === undefined)
        throw new Error(
          "The preparation time is missing. Restore the original queue before abandonment.",
        );
      return {
        requestId: upload.requestId,
        preparedAt: upload.preparedAt,
        confirmed: upload.abandonment === "confirmed",
      };
    });
    if (!cancellation) return { status: "not-found", jobId };
    if (cancellation.completed !== undefined)
      return { status: "completed", jobId, attachment: cancellation.completed };
    if (!cancellation.confirmed && cancellation.preparedAt !== undefined) {
      if (!this.remoteObjectStore?.abandonUpload)
        throw new Error(
          "The storage broker must support abandonment by original upload identity. The queue remains retained.",
        );
      try {
        await this.remoteObjectStore.abandonUpload({
          requestId: cancellation.requestId,
          preparedAt: cancellation.preparedAt,
        });
      } catch {
        await this.scheduleAbandonmentRetry(jobId);
        return { status: "pending", jobId };
      }
    }
    try {
      await artifacts.withExclusiveAccess(async () => {
        const state = await this.loadState();
        const job = state.jobs.find((item) => item.jobId === jobId);
        if (!job) return;
        const upload = state.uploads.get(jobId);
        if (
          upload?.requestId !== cancellation.requestId ||
          upload.preparedAt !== cancellation.preparedAt ||
          upload.abandonment === undefined
        )
          throw new MediaQueueConcurrentUpdateError();
        state.activeJobId = jobId;
        upload.abandonment = "confirmed";
        await this.saveState(state);
        await artifacts.delete(upload.requestId);
        state.jobs = state.jobs.filter((item) => item.jobId !== jobId);
        this.deleteJobSidecarState(state, job);
        await this.saveState(state);
      });
      return { status: "abandoned", jobId };
    } catch (error) {
      if (error instanceof MediaQueueConcurrentUpdateError) throw error;
      await this.scheduleAbandonmentRetry(jobId);
      return { status: "pending", jobId };
    }
  }

  private async scheduleAbandonmentRetry(jobId: string): Promise<void> {
    await this.config!.preparedUploads!.withExclusiveAccess(async () => {
      const state = await this.loadState();
      const job = state.jobs.find((item) => item.jobId === jobId);
      if (!job || state.uploads.get(jobId)?.abandonment === undefined) return;
      state.activeJobId = jobId;
      state.jobs = state.jobs.map((item) =>
        item.jobId === jobId
          ? {
              ...item,
              attempt: item.attempt + 1,
              notBefore: nextRetryTimestamp(item, Date.now(), this.config),
            }
          : item,
      );
      await this.saveState(state);
    });
  }

  async cleanup(
    input: SignalProtocolClientMediaCleanupInput,
    options: SignalProtocolClientMediaOperationOptions = {},
  ): Promise<SignalProtocolClientMediaCleanupResult> {
    const jobs = await this.enqueueCleanupJobs(input);
    const results: SignalProtocolClientMediaOperationResult[] = [];
    for (const job of jobs) {
      results.push(await this.processJob(job.jobId, options));
    }

    return {
      status: results.every((result) => result.status === "completed")
        ? "completed"
        : "pending",
      jobs: results,
    };
  }

  private async enqueueUploadJob(
    input: PlanMediaAttachmentUploadJobInput,
  ): Promise<MediaAttachmentBackgroundJob> {
    assertPreparedUploadByteLimit(this.config?.maxPreparedUploadBytes);
    const job = planMediaAttachmentUploadJob(input);
    const requestId =
      input.requestId ?? (await generateMediaAttachmentUploadRequestId());
    await this.updateState((state) => {
      const existingUpload =
        state.uploads.get(job.jobId) ??
        [...state.uploads.values()].find(
          (upload) =>
            upload.localMediaId === input.localMediaId ||
            upload.requestId === input.requestId,
        );
      if (existingUpload) {
        if (existingUpload.abandonment !== undefined)
          throw new Error(
            "This upload is being abandoned. Complete its cleanup before starting another upload.",
          );
        if (existingUpload.localMediaId !== input.localMediaId)
          throw new Error(
            "The queued upload request ID belongs to another local attachment.",
          );
        const incoming = {
          ...uploadOptionsFromStoredUpload({
            ...input,
            requestId: input.requestId ?? existingUpload.requestId,
          }),
          size: input.size,
        };
        const existing = {
          ...uploadOptionsFromStoredUpload(existingUpload),
          size: existingUpload.size,
        };
        if (JSON.stringify(incoming) !== JSON.stringify(existing)) {
          throw new Error(
            "The queued upload changed. Retry with the original upload input.",
          );
        }
        state.jobs = this.normalizeJobs([...state.jobs, job]);
        return;
      }
      state.jobs = this.normalizeJobs([...state.jobs, job]);
      state.uploads.set(job.jobId, {
        localMediaId: input.localMediaId,
        requestId,
        contentType: input.contentType,
        size: input.size,
        policy: input.policy,
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
      });
    });
    return job;
  }

  private async enqueueDownloadJob(
    input: PlanMediaAttachmentDownloadJobInput,
  ): Promise<MediaAttachmentBackgroundJob | null> {
    const job = planMediaAttachmentDownloadJob(input);
    if (!job) {
      return null;
    }

    const attachment = createMediaAttachmentPointer(input.attachment);
    await this.updateState((state) => {
      state.jobs = this.normalizeJobs([...state.jobs, job]);
      state.pointers.set(job.jobId, attachment);
    });
    return job;
  }

  private async enqueueCleanupJobs(
    input: PlanMediaAttachmentCleanupJobsInput,
  ): Promise<MediaAttachmentBackgroundJob[]> {
    const jobs = planMediaAttachmentCleanupJobs(input);
    if (jobs.length === 0) {
      return [];
    }

    await this.updateState((state) => {
      state.jobs = this.normalizeJobs([...state.jobs, ...jobs]);
    });
    return jobs;
  }

  async processPending(
    options: SignalProtocolClientProcessPendingMediaOptions = {},
  ): Promise<SignalProtocolClientMediaProcessResult> {
    return this.withStoreLock(() => this.processPendingLocked(options));
  }

  private async processPendingLocked(
    options: SignalProtocolClientProcessPendingMediaOptions,
  ): Promise<SignalProtocolClientMediaProcessResult> {
    const now = options.now ?? Date.now();
    const limit = options.limit ?? 5;
    const maxAttempts =
      this.config?.maxAttempts ??
      SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT;
    const initial = await this.loadState();
    const cancellations = initial.jobs
      .filter(
        (job) =>
          job.notBefore <= now &&
          initial.uploads.get(job.jobId)?.abandonment !== undefined,
      )
      .slice(0, limit);
    let abandoned = 0;
    for (const job of cancellations) {
      try {
        const result = await this.abandonUploadLocked(job.jobId);
        if (result.status === "abandoned" || result.status === "not-found")
          abandoned++;
      } catch (error) {
        if (error instanceof MediaQueueConcurrentUpdateError) throw error;
        await this.scheduleAbandonmentRetry(job.jobId);
      }
    }
    const state = await this.loadState();
    const dueJobs = state.jobs
      .filter(
        (job) =>
          job.notBefore <= now &&
          job.attempt < maxAttempts &&
          state.uploads.get(job.jobId)?.abandonment === undefined &&
          state.uploads.get(job.jobId)?.failureCode === undefined,
      )
      .slice(0, Math.max(0, limit - cancellations.length));
    const result = await this.processJobsLocked(
      state,
      dueJobs,
      options,
      now,
      maxAttempts,
    );
    return {
      ...result,
      attempted: result.attempted + cancellations.length,
      failed: result.failed + cancellations.length - abandoned,
      abandoned,
    };
  }

  private async processJob(
    jobId: string,
    options: SignalProtocolClientMediaOperationOptions,
  ): Promise<SignalProtocolClientMediaOperationResult> {
    return this.withStoreLock(async () => {
      const now = options.now ?? Date.now();
      const maxAttempts =
        this.config?.maxAttempts ??
        SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT;
      const state = await this.loadState();
      const job = state.jobs.find((candidate) => candidate.jobId === jobId);
      if (!job) {
        return { status: "failed", jobId };
      }
      if (job.notBefore > now) {
        return { status: "pending", jobId };
      }

      // Only an explicit upload call retries a retained broker refusal.
      const savedUpload = state.uploads.get(jobId);
      if (savedUpload?.abandonment !== undefined)
        throw new Error(
          "This upload is being abandoned. Retry cleanup with processPending().",
        );
      state.activeJobId = jobId;
      if (savedUpload?.failureCode !== undefined) {
        delete savedUpload.failureCode;
        await this.saveState(state);
      }

      const result = await this.processJobsLocked(
        state,
        [job],
        options,
        now,
        maxAttempts,
      );
      const execution = result.results.find(
        (candidate) => candidate.job.jobId === jobId,
      );
      if (execution?.status === MediaAttachmentJobExecutionStatus.Completed) {
        return { status: "completed", jobId, execution };
      }
      if (execution?.status === MediaAttachmentJobExecutionStatus.Skipped) {
        return { status: "skipped", jobId, execution };
      }
      const uploadFailure = result.uploadFailures.find(
        (candidate) => candidate.jobId === jobId,
      );
      if (uploadFailure)
        return { status: "failed", jobId, failure: uploadFailure.failure };
      return result.expired > 0
        ? { status: "failed", jobId }
        : { status: "pending", jobId };
    });
  }

  private async processJobsLocked(
    state: SignalProtocolClientMediaQueueState,
    jobs: MediaAttachmentBackgroundJob[],
    options: SignalProtocolClientMediaOperationOptions,
    now: number,
    maxAttempts: number,
  ): Promise<SignalProtocolClientMediaProcessResult> {
    const retained = new Map(state.jobs.map((job) => [job.jobId, job]));
    const results: MediaAttachmentJobExecutionResult[] = [];
    let completed = 0;
    let skipped = 0;
    let failed = 0;
    let expired = 0;
    const uploadFailures: SignalProtocolClientMediaProcessResult["uploadFailures"] =
      state.jobs.flatMap((job) => {
        const code = state.uploads.get(job.jobId)?.failureCode;
        return code === undefined
          ? []
          : [{ jobId: job.jobId, failure: remoteObjectUploadFailure(code) }];
      });

    if (jobs.length === 0) {
      return {
        attempted: 0,
        abandoned: 0,
        completed,
        skipped,
        failed,
        expired,
        results,
        uploadFailures,
      };
    }

    for (const job of jobs) {
      state.activeJobId = job.jobId;
      // Persist progress from each job before external effects for the next job.
      state.jobs = [...retained.values()];
      if (
        job.operation === MediaAttachmentJobOperation.Upload &&
        !this.config?.preparedUploads
      ) {
        throw new Error(
          "Configure media.preparedUploads with durable local file storage before uploading.",
        );
      }
      if (job.operation === MediaAttachmentJobOperation.Upload)
        assertPreparedUploadByteLimit(this.config?.maxPreparedUploadBytes);
      try {
        const execution = await executeMediaAttachmentJob(
          job,
          this.createExecutionOptions(job, state, options),
        );
        if (execution.status === MediaAttachmentJobExecutionStatus.Completed) {
          if (job.operation === MediaAttachmentJobOperation.Upload) {
            const upload = state.uploads.get(job.jobId);
            if (upload?.preparedFingerprint)
              await this.config!.preparedUploads!.withExclusiveAccess(
                async () => {
                  await this.saveState(state);
                  await this.config!.preparedUploads!.delete(upload.requestId);
                },
              );
          }
          completed += 1;
          retained.delete(job.jobId);
          this.deleteJobSidecarState(state, job);
        } else {
          skipped += 1;
          retained.delete(job.jobId);
          this.deleteJobSidecarState(state, job);
        }
        results.push(execution);
      } catch (error) {
        if (error instanceof MediaQueueConcurrentUpdateError) throw error;
        failed += 1;
        const upload = state.uploads.get(job.jobId);
        if (
          job.operation === MediaAttachmentJobOperation.Upload &&
          upload &&
          error instanceof RemoteObjectUploadError
        ) {
          upload.failureCode = error.code;
          uploadFailures.push({
            jobId: job.jobId,
            failure: remoteObjectUploadFailure(error.code),
          });
          retained.set(job.jobId, { ...job, attempt: job.attempt + 1 });
          state.jobs = [...retained.values()];
          await this.saveState(state);
          continue;
        }
        const nextAttempt = job.attempt + 1;
        if (nextAttempt >= maxAttempts) {
          expired += 1;
          // The artifact can commit before its reply or queue fingerprint persists.
          if (
            job.operation === MediaAttachmentJobOperation.Upload &&
            (upload?.preparationStarted || upload?.preparedFingerprint)
          ) {
            retained.set(job.jobId, { ...job, attempt: nextAttempt });
            continue;
          }
          retained.delete(job.jobId);
          this.deleteJobSidecarState(state, job);
          continue;
        }

        retained.set(job.jobId, {
          ...job,
          attempt: nextAttempt,
          notBefore: nextRetryTimestamp(job, now, this.config),
        });
      }
      state.jobs = [...retained.values()];
      await this.saveState(state);
    }

    state.jobs = this.normalizeJobs([...retained.values()]);
    await this.saveState(state);

    return {
      attempted: jobs.length,
      abandoned: 0,
      completed,
      skipped,
      failed,
      expired,
      results,
      uploadFailures,
    };
  }

  /** Persist broker identity before the transfer code receives its short-lived URL. */
  private uploadBrokerForJob(
    job: MediaAttachmentBackgroundJob,
    state: SignalProtocolClientMediaQueueState,
    broker: SignalProtocolRemoteObjectStore,
  ): SignalProtocolRemoteObjectStore {
    return {
      createUpload: async (input) => {
        const upload = state.uploads.get(job.jobId);
        if (
          !upload?.preparedFingerprint ||
          input.requestId !== upload.requestId
        ) {
          throw new MediaAttachmentError(
            "The upload has no matching durable preparation.",
            MediaAttachmentErrorCode.UploadIdentityChanged,
          );
        }
        const grant = await broker.createUpload(input);
        if (
          typeof grant.objectId !== "string" ||
          grant.objectId.length === 0 ||
          (upload.remoteObjectId !== undefined &&
            upload.remoteObjectId !== grant.objectId)
        ) {
          throw new MediaAttachmentError(
            "The broker changed the saved upload identity.",
            MediaAttachmentErrorCode.UploadIdentityChanged,
          );
        }
        upload.remoteObjectId = grant.objectId;
        // Repeat this write after an uncertain result, including retries within one invocation.
        await this.saveState(state);
        return grant;
      },
      createDownload: (input) => broker.createDownload(input),
      ...(broker.reconcileUpload
        ? {
            reconcileUpload: async (input: { objectId: string }) => {
              if (
                state.uploads.get(job.jobId)?.remoteObjectId !== input.objectId
              ) {
                throw new MediaAttachmentError(
                  "The reconciliation request differs from the saved upload identity.",
                  MediaAttachmentErrorCode.UploadIdentityChanged,
                );
              }
              return broker.reconcileUpload!(input);
            },
          }
        : {}),
      completeUpload: async (input) => {
        const upload = state.uploads.get(job.jobId);
        if (
          !upload?.remoteObjectId ||
          input.objectId !== upload.remoteObjectId
        ) {
          throw new MediaAttachmentError(
            "The completion request differs from the saved upload identity.",
            MediaAttachmentErrorCode.UploadIdentityChanged,
          );
        }
        upload.transferCompletedAt ??= Date.now();
        // Persist successful transfer before completion can change the remote state.
        await this.saveState(state);
        await broker.completeUpload?.(input);
      },
      ...(broker.deleteObject
        ? { deleteObject: (input) => broker.deleteObject!(input) }
        : {}),
    };
  }

  private async recoverCompletedUpload(
    job: MediaAttachmentBackgroundJob,
    state: SignalProtocolClientMediaQueueState,
    broker: SignalProtocolRemoteObjectStore,
    options: SignalProtocolClientMediaOperationOptions,
  ): Promise<MediaAttachmentPointer | null> {
    const completed = state.pointers.get(job.jobId);
    if (completed) return completed;
    const upload = state.uploads.get(job.jobId);
    if (!upload?.remoteObjectId) return null;
    if (upload.transferCompletedAt === undefined && !broker.reconcileUpload)
      return null;
    if (options.signal?.aborted)
      throw new MediaAttachmentError(
        "Media attachment operation cancelled",
        MediaAttachmentErrorCode.Cancelled,
      );
    const prepared = await this.config!.preparedUploads!.load(upload.requestId);
    if (
      !prepared ||
      !preparedUploadMatchesQueue(upload, prepared) ||
      (await preparedUploadFingerprint(prepared)) !==
        upload.preparedFingerprint ||
      prepared.ciphertext.length !== prepared.pointer.ciphertextSize ||
      bytesToBase64(await sha256(prepared.ciphertext)) !==
        prepared.pointer.digest
    ) {
      throw new Error(
        "The saved upload preparation changed. Restore its original local record.",
      );
    }
    const completedAt = upload.transferCompletedAt ?? Date.now();
    const attachment = validateMediaAttachmentPolicy(
      {
        ...prepared.pointer,
        storageId: upload.remoteObjectId,
        uploadTimestamp: completedAt,
      },
      upload.policy ?? options.policy,
    );
    if (upload.transferCompletedAt === undefined) {
      const receipt = await broker.reconcileUpload!({
        objectId: upload.remoteObjectId,
      });
      if (receipt === null) return null;
      if (
        !matchesUploadReceipt(receipt, {
          objectId: upload.remoteObjectId,
          contentLength: prepared.ciphertext.length,
          digest: await sha256(prepared.ciphertext),
        })
      ) {
        throw new MediaAttachmentError(
          "The stored upload differs from its immutable preparation.",
          MediaAttachmentErrorCode.UploadIdentityChanged,
        );
      }
      upload.transferCompletedAt = completedAt;
      await this.saveState(state);
    }
    if (options.signal?.aborted)
      throw new MediaAttachmentError(
        "Media attachment operation cancelled",
        MediaAttachmentErrorCode.Cancelled,
      );
    await broker.completeUpload?.({ objectId: attachment.storageId });
    return attachment;
  }

  private createExecutionOptions(
    job: MediaAttachmentBackgroundJob,
    state: SignalProtocolClientMediaQueueState,
    options: SignalProtocolClientMediaOperationOptions,
  ): ExecuteMediaAttachmentJobOptions {
    const remoteObjectStore = this.remoteObjectStore ?? localOnlyObjectStore;
    if (
      !this.remoteObjectStore &&
      (job.operation === MediaAttachmentJobOperation.Upload ||
        job.operation === MediaAttachmentJobOperation.Download ||
        job.operation === MediaAttachmentJobOperation.DeleteRemote)
    ) {
      throw new Error(
        "Cannot process Signal Protocol media operation: remoteObjectStore is not " +
          "configured on SignalProtocolClient.",
      );
    }

    return {
      remoteObjectStore:
        job.operation === MediaAttachmentJobOperation.Upload
          ? this.uploadBrokerForJob(job, state, remoteObjectStore)
          : remoteObjectStore,
      transfer: options.transfer,
      retry: options.retry,
      policy: options.policy,
      signal: options.signal,
      onProgress: options.onProgress,
      onCheckpoint: options.onCheckpoint,
      loadUploadData: async (job) => {
        const upload = state.uploads.get(job.jobId);
        if (!upload) {
          return null;
        }
        const preparedUploads = this.config?.preparedUploads;
        if (!preparedUploads)
          throw new Error(
            "Configure media.preparedUploads with durable local file storage before uploading.",
          );
        let prepared = await preparedUploads.load(upload.requestId);
        if (prepared) {
          if (
            !preparedUploadMatchesQueue(upload, prepared) ||
            (upload.preparedFingerprint !== undefined &&
              (await preparedUploadFingerprint(prepared)) !==
                upload.preparedFingerprint)
          ) {
            throw new Error(
              "The saved upload preparation changed. Restore its original local record.",
            );
          }
          if (upload.preparedFingerprint === undefined) {
            upload.preparedFingerprint =
              await preparedUploadFingerprint(prepared);
            await this.saveState(state);
          }
          return { prepared, options: uploadOptionsFromStoredUpload(upload) };
        } else if (upload.preparedFingerprint !== undefined) {
          throw new Error(
            "The saved upload preparation is missing. Restore its original local record.",
          );
        }
        if (!this.config?.loadLocalAttachment) return null;

        const draft = { ...upload, job };
        delete draft.preparedFingerprint;
        delete draft.preparationStarted;
        delete draft.preparedAt;
        delete draft.abandonment;
        delete draft.remoteObjectId;
        delete draft.transferCompletedAt;
        delete draft.callbackDelivered;
        const loaded = normalizeLoadedLocalAttachment(
          await this.config.loadLocalAttachment(draft),
        );
        if (!loaded) {
          return null;
        }

        const storedOptions = uploadOptionsFromStoredUpload(upload);
        for (const key of Object.keys(storedOptions) as Array<
          keyof typeof storedOptions
        >) {
          if (
            loaded.options?.[key] !== undefined &&
            JSON.stringify(loaded.options[key]) !==
              JSON.stringify(storedOptions[key])
          ) {
            throw new Error(
              "The attachment loader changed the queued upload input.",
            );
          }
        }
        if (loaded.data.length !== upload.size)
          throw new Error(
            "The attachment length differs from the queued upload.",
          );
        await this.saveState(state);
        const candidate = await prepareMediaAttachmentUploadData(loaded.data, {
          ...loaded.options,
          ...storedOptions,
          signal: options.signal,
          onProgress: options.onProgress,
        });
        // Preserve intent if artifact persistence succeeds but its result is lost.
        prepared = await preparedUploads.withExclusiveAccess(async () => {
          upload.preparationStarted = true;
          upload.preparedAt = candidate.preparedAt;
          await this.saveState(state);
          return preparedUploads.createIfAbsent(candidate);
        });
        if (
          !samePreparedUploadIntent(
            candidate,
            prepared,
            upload.clientUuid !== undefined,
          )
        ) {
          throw new Error(
            "The stored preparation belongs to different upload input.",
          );
        }
        upload.preparedFingerprint = await preparedUploadFingerprint(prepared);
        await this.saveState(state);
        return { prepared, options: { ...loaded.options, ...storedOptions } };
      },
      loadUploadedAttachment: (job) =>
        this.recoverCompletedUpload(job, state, remoteObjectStore, options),
      loadAttachmentPointer: async (job) =>
        state.pointers.get(job.jobId) ?? null,
      saveUploadedAttachment: async (job, attachment) => {
        const upload = state.uploads.get(job.jobId);
        if (!upload) {
          return;
        }
        if (upload.callbackDelivered) return;
        state.pointers.set(job.jobId, createMediaAttachmentPointer(attachment));
        await this.saveState(state);
        await this.config?.saveUploadedAttachment?.({
          job,
          localMediaId: upload.localMediaId,
          attachment,
        });
        upload.callbackDelivered = true;
        await this.saveState(state);
      },
      saveDownloadedAttachment: async (job, downloaded) => {
        await this.config?.saveDownloadedAttachment?.({
          job,
          attachmentId: job.attachmentId,
          downloaded,
        });
      },
      deleteLocalAttachment: async (job) => {
        await this.config?.deleteLocalAttachment?.({
          job,
          attachmentId: job.attachmentId,
          storageId: job.storageId,
        });
      },
      syncDelete: async (job, deleteSync) => {
        await this.config?.syncDelete?.({ job, deleteSync });
      },
    };
  }

  private deleteJobSidecarState(
    state: SignalProtocolClientMediaQueueState,
    job: MediaAttachmentBackgroundJob,
  ): void {
    state.uploads.delete(job.jobId);
    state.pointers.delete(job.jobId);
  }

  private normalizeJobs(
    jobs: readonly MediaAttachmentBackgroundJob[],
  ): MediaAttachmentBackgroundJob[] {
    return normalizeJobs(
      jobs,
      this.config?.maxJobs ??
        SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_JOBS_DEFAULT,
    );
  }

  private async withStoreLock<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.storeLock;
    let release: () => void = () => {};
    this.storeLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;

    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async updateState(
    mutator: (state: SignalProtocolClientMediaQueueState) => void,
  ): Promise<void> {
    await this.withStoreLock(async () => {
      for (let attempt = 0; attempt < 16; attempt++) {
        const state = await this.loadState();
        mutator(state);
        try {
          await this.saveState(state);
          return;
        } catch (error) {
          if (!(error instanceof MediaQueueConcurrentUpdateError)) throw error;
        }
      }
      throw new MediaQueueConcurrentUpdateError();
    });
  }

  private async loadState(): Promise<SignalProtocolClientMediaQueueState> {
    const raw = await this.storage.getMetadata(
      SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY,
    );
    if (!raw) {
      const state = { jobs: [], uploads: new Map(), pointers: new Map() };
      this.queuePersistence.capture(state, raw);
      return state;
    }

    try {
      const parsed = JSON.parse(
        raw,
      ) as Partial<StoredSignalProtocolClientMediaQueue>;
      if (parsed.version !== 1) {
        throw new Error("Invalid media queue version.");
      }
      if (
        !Array.isArray(parsed.jobs) ||
        !isRecord(parsed.uploads) ||
        !isRecord(parsed.pointers)
      )
        throw new Error("Invalid media queue structure.");

      const uploads = new Map<string, StoredSignalProtocolClientMediaUpload>();
      for (const [jobId, upload] of Object.entries(parsed.uploads ?? {})) {
        if (isStoredUpload(upload)) {
          uploads.set(jobId, upload);
        } else throw new Error("Invalid media upload record.");
      }

      const pointers = new Map<string, MediaAttachmentPointer>();
      for (const [jobId, pointer] of Object.entries(parsed.pointers ?? {})) {
        const normalized = normalizePointer(pointer);
        if (normalized) {
          pointers.set(jobId, normalized);
        } else throw new Error("Invalid media pointer record.");
      }

      for (const job of parsed.jobs) {
        if (job.operation === MediaAttachmentJobOperation.Upload) {
          const upload = uploads.get(job.jobId);
          if (
            !upload ||
            (upload.remoteObjectId !== undefined &&
              !upload.preparedFingerprint) ||
            (upload.transferCompletedAt !== undefined &&
              !upload.remoteObjectId) ||
            (pointers.has(job.jobId) &&
              (upload.transferCompletedAt === undefined ||
                pointers.get(job.jobId)!.storageId !==
                  upload.remoteObjectId)) ||
            (upload.callbackDelivered && !pointers.has(job.jobId))
          ) {
            throw new Error("Incomplete media upload record.");
          }
        }
      }

      const state = {
        jobs: this.normalizeJobs(parsed.jobs),
        uploads,
        pointers,
      };
      this.queuePersistence.capture(state, raw);
      return state;
    } catch {
      throw new Error(
        "The saved media queue is invalid. Restore its original local state before retrying.",
      );
    }
  }

  private async saveState(
    state: SignalProtocolClientMediaQueueState,
  ): Promise<void> {
    await this.queuePersistence.save(
      state,
      JSON.stringify({
        version: 1,
        jobs: this.normalizeJobs(state.jobs),
        uploads: Object.fromEntries(state.uploads),
        pointers: Object.fromEntries(state.pointers),
      } satisfies StoredSignalProtocolClientMediaQueue),
      this.config?.maxJobs ??
        SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_JOBS_DEFAULT,
      state.activeJobId,
      this.config?.maxPreparedUploadBytes,
    );
  }
}
