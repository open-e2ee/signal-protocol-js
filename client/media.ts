import type { SignalRemoteObjectStore } from '../remote/object-store';
import type { ISignalLocalStore } from '../types/api';
import {
  createMediaAttachmentId,
  createMediaAttachmentPointer,
  executeMediaAttachmentJob,
  generateMediaAttachmentUploadRequestId,
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
  type MediaAttachmentPolicy,
  type MediaAttachmentProgressCallback,
  type MediaAttachmentRetryOptions,
  type MediaAttachmentTransfer,
  type PlanMediaAttachmentCleanupJobsInput,
  type PlanMediaAttachmentDownloadJobInput,
  type PlanMediaAttachmentUploadJobInput,
  type PrepareMediaAttachmentUploadOptions,
  type ResolvedMediaAttachment,
} from '../media';

const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY = 'signal:mediaQueue:v1';
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_JOBS_DEFAULT = 200;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT = 5;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_BASE_RETRY_DELAY_MS_DEFAULT = 30_000;
const SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_RETRY_DELAY_MS_DEFAULT = 60 * 60 * 1000;

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
}

export interface SignalProtocolClientLoadLocalAttachmentInput extends StoredSignalProtocolClientMediaUpload {
  job: MediaAttachmentBackgroundJob;
}

export interface SignalProtocolClientLoadedLocalAttachment {
  data: Uint8Array;
  options?: Omit<PrepareMediaAttachmentUploadOptions, 'remoteObjectStore'>;
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
  /**
   * Load app-owned local bytes for a queued upload.
   *
   * The Signal Protocol package owns encryption and upload execution. The app owns draft
   * files, cache paths, and file permissions, so bytes enter the queue through
   * this callback instead of hidden package storage.
   */
  loadLocalAttachment?: (
    input: SignalProtocolClientLoadLocalAttachmentInput
  ) => Promise<Uint8Array | SignalProtocolClientLoadedLocalAttachment | null>;

  /**
   * Persist the encrypted attachment pointer produced by a queued upload.
   */
  saveUploadedAttachment?: (
    input: SignalProtocolClientSaveUploadedAttachmentInput
  ) => Promise<void>;

  /**
   * Persist plaintext bytes returned by a queued download.
   */
  saveDownloadedAttachment?: (
    input: SignalProtocolClientSaveDownloadedAttachmentInput
  ) => Promise<void>;

  /**
   * Delete app-owned local cache state for a cleanup job.
   */
  deleteLocalAttachment?: (input: SignalProtocolClientDeleteLocalAttachmentInput) => Promise<void>;

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
   * Maximum attempts before a failing job is removed.
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
  completed: number;
  skipped: number;
  failed: number;
  expired: number;
  results: MediaAttachmentJobExecutionResult[];
}

interface StorageBackedSignalProtocolClientMediaOptions {
  storage: ISignalLocalStore;
  remoteObjectStore?: SignalRemoteObjectStore;
  config?: SignalProtocolClientMediaConfig;
}

export type SignalProtocolClientMediaUploadInput = PlanMediaAttachmentUploadJobInput;
export type SignalProtocolClientMediaDownloadInput = PlanMediaAttachmentDownloadJobInput;
export type SignalProtocolClientMediaCleanupInput = PlanMediaAttachmentCleanupJobsInput;

export interface SignalProtocolClientMediaCompletedResult {
  status: 'completed';
  jobId: string;
  execution: MediaAttachmentJobExecutionResult;
}

export interface SignalProtocolClientMediaPendingResult {
  status: 'pending';
  jobId: string;
}

export interface SignalProtocolClientMediaSkippedResult {
  status: 'skipped';
  jobId: string;
  execution: MediaAttachmentJobExecutionResult;
}

export interface SignalProtocolClientMediaFailedResult {
  status: 'failed';
  jobId: string;
}

export type SignalProtocolClientMediaOperationResult =
  | SignalProtocolClientMediaCompletedResult
  | SignalProtocolClientMediaPendingResult
  | SignalProtocolClientMediaSkippedResult
  | SignalProtocolClientMediaFailedResult;

export interface SignalProtocolClientMediaUploadCompletedResult {
  status: 'completed';
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
  status: 'skipped';
  reason: 'not-needed';
  attachmentId: string;
}

export interface SignalProtocolClientMediaDownloadCompletedResult {
  status: 'completed';
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
      status: 'completed';
      jobs: SignalProtocolClientMediaOperationResult[];
    }
  | {
      status: 'pending';
      jobs: SignalProtocolClientMediaOperationResult[];
    };

export interface SignalProtocolClientMedia {
  upload(
    input: SignalProtocolClientMediaUploadInput,
    options?: SignalProtocolClientMediaOperationOptions
  ): Promise<SignalProtocolClientMediaUploadResult>;

  download(
    input: SignalProtocolClientMediaDownloadInput,
    options?: SignalProtocolClientMediaOperationOptions
  ): Promise<SignalProtocolClientMediaDownloadResult>;

  cleanup(
    input: SignalProtocolClientMediaCleanupInput,
    options?: SignalProtocolClientMediaOperationOptions
  ): Promise<SignalProtocolClientMediaCleanupResult>;

  processPending(
    options?: SignalProtocolClientProcessPendingMediaOptions
  ): Promise<SignalProtocolClientMediaProcessResult>;
}

const localOnlyObjectStore: SignalRemoteObjectStore = {
  async createUpload() {
    throw new Error('Signal Protocol media operation requires remoteObjectStore for upload');
  },
  async createDownload() {
    throw new Error('Signal Protocol media operation requires remoteObjectStore for download');
  },
  async deleteObject() {
    throw new Error('Signal Protocol media operation requires remoteObjectStore for remote delete');
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
  right: MediaAttachmentBackgroundJob
): number {
  const priorityDelta = priorityRank(right.priority) - priorityRank(left.priority);
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
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isInteger(value: unknown): value is number {
  return Number.isSafeInteger(value);
}

function isMediaAttachmentJob(value: unknown): value is MediaAttachmentBackgroundJob {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.jobId === 'string' &&
    Object.values(MediaAttachmentJobOperation).includes(value.operation as never) &&
    Object.values(MediaAttachmentJobSource).includes(value.source as never) &&
    Object.values(MediaAttachmentJobPriority).includes(value.priority as never) &&
    typeof value.requiresNetwork === 'boolean' &&
    typeof value.attachmentId === 'string' &&
    isInteger(value.attempt) &&
    isInteger(value.createdAt) &&
    isInteger(value.notBefore) &&
    (value.storageId === undefined || typeof value.storageId === 'string') &&
    (value.deliveryId === undefined || typeof value.deliveryId === 'string') &&
    (value.reason === undefined || typeof value.reason === 'string')
  );
}

function normalizePointer(value: unknown): MediaAttachmentPointer | null {
  try {
    return createMediaAttachmentPointer(value as never);
  } catch {
    return null;
  }
}

function isStoredUpload(value: unknown): value is StoredSignalProtocolClientMediaUpload {
  return (
    isRecord(value) &&
    typeof value.localMediaId === 'string' &&
    value.localMediaId.length > 0 &&
    typeof value.requestId === 'string' &&
    value.requestId.length > 0 &&
    typeof value.contentType === 'string' &&
    value.contentType.length > 0 &&
    isInteger(value.size) &&
    value.size >= 0
  );
}

function mergeJob(
  existing: MediaAttachmentBackgroundJob,
  incoming: MediaAttachmentBackgroundJob
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
  maxJobs: number
): MediaAttachmentBackgroundJob[] {
  const deduped = new Map<string, MediaAttachmentBackgroundJob>();

  for (const job of jobs) {
    if (!isMediaAttachmentJob(job)) {
      continue;
    }

    const existing = deduped.get(job.jobId);
    deduped.set(job.jobId, existing ? mergeJob(existing, job) : job);
  }

  return [...deduped.values()].sort(compareMediaAttachmentJobs).slice(0, maxJobs);
}

function nextRetryTimestamp(
  job: MediaAttachmentBackgroundJob,
  now: number,
  config?: SignalProtocolClientMediaConfig
): number {
  const baseDelay =
    config?.baseRetryDelayMs ?? SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_BASE_RETRY_DELAY_MS_DEFAULT;
  const maxDelay =
    config?.maxRetryDelayMs ?? SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_RETRY_DELAY_MS_DEFAULT;
  const delay = Math.min(maxDelay, baseDelay * 2 ** Math.max(0, job.attempt));
  return now + delay;
}

function normalizeLoadedLocalAttachment(
  value: Uint8Array | SignalProtocolClientLoadedLocalAttachment | null
): SignalProtocolClientLoadedLocalAttachment | null {
  if (!value) {
    return null;
  }

  return value instanceof Uint8Array ? { data: value } : value;
}

function uploadOptionsFromStoredUpload(
  upload: StoredSignalProtocolClientMediaUpload
): Omit<PrepareMediaAttachmentUploadOptions, 'remoteObjectStore'> {
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

/** @internal */
export class StorageBackedSignalProtocolClientMedia implements SignalProtocolClientMedia {
  private readonly storage: ISignalLocalStore;
  private readonly remoteObjectStore?: SignalRemoteObjectStore;
  private readonly config?: SignalProtocolClientMediaConfig;
  private storeLock: Promise<void> = Promise.resolve();

  constructor(options: StorageBackedSignalProtocolClientMediaOptions) {
    this.storage = options.storage;
    this.remoteObjectStore = options.remoteObjectStore;
    this.config = options.config;
  }

  async upload(
    input: SignalProtocolClientMediaUploadInput,
    options: SignalProtocolClientMediaOperationOptions = {}
  ): Promise<SignalProtocolClientMediaUploadResult> {
    const job = await this.enqueueUploadJob(input);
    const result = await this.processJob(job.jobId, options);
    if (result.status === 'completed' && result.execution.uploadedAttachment) {
      return {
        status: 'completed',
        jobId: job.jobId,
        attachment: result.execution.uploadedAttachment,
        execution: result.execution,
      };
    }
    if (result.status === 'completed') {
      return { status: 'failed', jobId: job.jobId };
    }
    return result;
  }

  async download(
    input: SignalProtocolClientMediaDownloadInput,
    options: SignalProtocolClientMediaOperationOptions = {}
  ): Promise<SignalProtocolClientMediaDownloadResult> {
    const job = await this.enqueueDownloadJob(input);
    if (!job) {
      const attachment = createMediaAttachmentPointer(input.attachment);
      return {
        status: 'skipped',
        reason: 'not-needed',
        attachmentId: createMediaAttachmentId(attachment),
      };
    }

    const result = await this.processJob(job.jobId, options);
    if (result.status === 'completed' && result.execution.downloadedAttachment) {
      return {
        status: 'completed',
        jobId: job.jobId,
        attachmentId: job.attachmentId,
        downloaded: result.execution.downloadedAttachment,
        execution: result.execution,
      };
    }
    if (result.status === 'completed') {
      return { status: 'failed', jobId: job.jobId };
    }
    return result;
  }

  async cleanup(
    input: SignalProtocolClientMediaCleanupInput,
    options: SignalProtocolClientMediaOperationOptions = {}
  ): Promise<SignalProtocolClientMediaCleanupResult> {
    const jobs = await this.enqueueCleanupJobs(input);
    const results: SignalProtocolClientMediaOperationResult[] = [];
    for (const job of jobs) {
      results.push(await this.processJob(job.jobId, options));
    }

    return {
      status: results.every((result) => result.status === 'completed') ? 'completed' : 'pending',
      jobs: results,
    };
  }

  private async enqueueUploadJob(
    input: PlanMediaAttachmentUploadJobInput
  ): Promise<MediaAttachmentBackgroundJob> {
    const job = planMediaAttachmentUploadJob(input);
    const requestId = input.requestId ?? (await generateMediaAttachmentUploadRequestId());
    await this.updateState((state) => {
      const existingUpload = state.uploads.get(job.jobId);
      state.jobs = this.normalizeJobs([...state.jobs, job]);
      state.uploads.set(job.jobId, {
        localMediaId: input.localMediaId,
        requestId: existingUpload?.requestId ?? requestId,
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
    input: PlanMediaAttachmentDownloadJobInput
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
    input: PlanMediaAttachmentCleanupJobsInput
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
    options: SignalProtocolClientProcessPendingMediaOptions = {}
  ): Promise<SignalProtocolClientMediaProcessResult> {
    return this.withStoreLock(() => this.processPendingLocked(options));
  }

  private async processPendingLocked(
    options: SignalProtocolClientProcessPendingMediaOptions
  ): Promise<SignalProtocolClientMediaProcessResult> {
    const now = options.now ?? Date.now();
    const limit = options.limit ?? 5;
    const maxAttempts =
      this.config?.maxAttempts ?? SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT;
    const state = await this.loadState();
    const dueJobs = state.jobs.filter((job) => job.notBefore <= now).slice(0, limit);
    return this.processJobsLocked(state, dueJobs, options, now, maxAttempts);
  }

  private async processJob(
    jobId: string,
    options: SignalProtocolClientMediaOperationOptions
  ): Promise<SignalProtocolClientMediaOperationResult> {
    return this.withStoreLock(async () => {
      const now = options.now ?? Date.now();
      const maxAttempts =
        this.config?.maxAttempts ?? SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_ATTEMPTS_DEFAULT;
      const state = await this.loadState();
      const job = state.jobs.find((candidate) => candidate.jobId === jobId);
      if (!job) {
        return { status: 'failed', jobId };
      }
      if (job.notBefore > now) {
        return { status: 'pending', jobId };
      }

      const result = await this.processJobsLocked(state, [job], options, now, maxAttempts);
      const execution = result.results.find((candidate) => candidate.job.jobId === jobId);
      if (execution?.status === MediaAttachmentJobExecutionStatus.Completed) {
        return { status: 'completed', jobId, execution };
      }
      if (execution?.status === MediaAttachmentJobExecutionStatus.Skipped) {
        return { status: 'skipped', jobId, execution };
      }
      return result.expired > 0 ? { status: 'failed', jobId } : { status: 'pending', jobId };
    });
  }

  private async processJobsLocked(
    state: SignalProtocolClientMediaQueueState,
    jobs: MediaAttachmentBackgroundJob[],
    options: SignalProtocolClientMediaOperationOptions,
    now: number,
    maxAttempts: number
  ): Promise<SignalProtocolClientMediaProcessResult> {
    const retained = new Map(state.jobs.map((job) => [job.jobId, job]));
    const results: MediaAttachmentJobExecutionResult[] = [];
    let completed = 0;
    let skipped = 0;
    let failed = 0;
    let expired = 0;

    if (jobs.length === 0) {
      return { attempted: 0, completed, skipped, failed, expired, results };
    }

    for (const job of jobs) {
      try {
        const execution = await executeMediaAttachmentJob(
          job,
          this.createExecutionOptions(job, state, options)
        );
        results.push(execution);

        if (execution.status === MediaAttachmentJobExecutionStatus.Completed) {
          completed += 1;
          retained.delete(job.jobId);
          this.deleteJobSidecarState(state, job);
        } else {
          skipped += 1;
          retained.delete(job.jobId);
          this.deleteJobSidecarState(state, job);
        }
      } catch {
        failed += 1;
        const nextAttempt = job.attempt + 1;
        if (nextAttempt >= maxAttempts) {
          expired += 1;
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
    }

    await this.saveState({
      jobs: this.normalizeJobs([...retained.values()]),
      uploads: state.uploads,
      pointers: state.pointers,
    });

    return {
      attempted: jobs.length,
      completed,
      skipped,
      failed,
      expired,
      results,
    };
  }

  private createExecutionOptions(
    job: MediaAttachmentBackgroundJob,
    state: SignalProtocolClientMediaQueueState,
    options: SignalProtocolClientMediaOperationOptions
  ): ExecuteMediaAttachmentJobOptions {
    const remoteObjectStore = this.remoteObjectStore ?? localOnlyObjectStore;
    if (
      !this.remoteObjectStore &&
      (job.operation === MediaAttachmentJobOperation.Upload ||
        job.operation === MediaAttachmentJobOperation.Download ||
        job.operation === MediaAttachmentJobOperation.DeleteRemote)
    ) {
      throw new Error(
        'Cannot process Signal Protocol media operation: remoteObjectStore is not ' +
          'configured on SignalProtocolClient.'
      );
    }

    return {
      remoteObjectStore,
      transfer: options.transfer,
      retry: options.retry,
      policy: options.policy,
      signal: options.signal,
      onProgress: options.onProgress,
      onCheckpoint: options.onCheckpoint,
      loadUploadData: async (job) => {
        const upload = state.uploads.get(job.jobId);
        if (!upload || !this.config?.loadLocalAttachment) {
          return null;
        }

        const loaded = normalizeLoadedLocalAttachment(
          await this.config.loadLocalAttachment({ ...upload, job })
        );
        if (!loaded) {
          return null;
        }

        return {
          data: loaded.data,
          options: {
            ...uploadOptionsFromStoredUpload(upload),
            ...loaded.options,
          },
        };
      },
      loadAttachmentPointer: async (job) => state.pointers.get(job.jobId) ?? null,
      saveUploadedAttachment: async (job, attachment) => {
        const upload = state.uploads.get(job.jobId);
        if (!upload) {
          return;
        }

        await this.config?.saveUploadedAttachment?.({
          job,
          localMediaId: upload.localMediaId,
          attachment,
        });
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
    job: MediaAttachmentBackgroundJob
  ): void {
    state.uploads.delete(job.jobId);
    state.pointers.delete(job.jobId);
  }

  private normalizeJobs(
    jobs: readonly MediaAttachmentBackgroundJob[]
  ): MediaAttachmentBackgroundJob[] {
    return normalizeJobs(
      jobs,
      this.config?.maxJobs ?? SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_MAX_JOBS_DEFAULT
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
    mutator: (state: SignalProtocolClientMediaQueueState) => void
  ): Promise<void> {
    await this.withStoreLock(async () => {
      const state = await this.loadState();
      mutator(state);
      await this.saveState(state);
    });
  }

  private async loadState(): Promise<SignalProtocolClientMediaQueueState> {
    const raw = await this.storage.getMetadata(SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY);
    if (!raw) {
      return { jobs: [], uploads: new Map(), pointers: new Map() };
    }

    try {
      const parsed = JSON.parse(raw) as Partial<StoredSignalProtocolClientMediaQueue>;
      if (parsed.version !== 1) {
        return { jobs: [], uploads: new Map(), pointers: new Map() };
      }

      const uploads = new Map<string, StoredSignalProtocolClientMediaUpload>();
      for (const [jobId, upload] of Object.entries(parsed.uploads ?? {})) {
        if (isStoredUpload(upload)) {
          uploads.set(jobId, upload);
        }
      }

      const pointers = new Map<string, MediaAttachmentPointer>();
      for (const [jobId, pointer] of Object.entries(parsed.pointers ?? {})) {
        const normalized = normalizePointer(pointer);
        if (normalized) {
          pointers.set(jobId, normalized);
        }
      }

      return {
        jobs: this.normalizeJobs(Array.isArray(parsed.jobs) ? parsed.jobs : []),
        uploads,
        pointers,
      };
    } catch {
      return { jobs: [], uploads: new Map(), pointers: new Map() };
    }
  }

  private async saveState(state: SignalProtocolClientMediaQueueState): Promise<void> {
    await this.storage.setMetadata(
      SIGNAL_PROTOCOL_CLIENT_MEDIA_QUEUE_METADATA_KEY,
      JSON.stringify({
        version: 1,
        jobs: this.normalizeJobs(state.jobs),
        uploads: Object.fromEntries(state.uploads),
        pointers: Object.fromEntries(state.pointers),
      } satisfies StoredSignalProtocolClientMediaQueue)
    );
  }
}
