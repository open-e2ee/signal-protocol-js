import type { SignalProtocolLocalStore } from "../types/api";
import type { MediaAttachmentBackgroundJob } from "../media";
import { assertQueuedUploadCapacity } from "./media-upload-budget";

interface QueueDocument {
  version: 1;
  jobs: MediaAttachmentBackgroundJob[];
  uploads: Record<string, unknown>;
  pointers: Record<string, unknown>;
}

export class MediaQueueConcurrentUpdateError extends Error {
  constructor() {
    super(
      "The media queue changed in another client. Retry from the current local store.",
    );
    this.name = "MediaQueueConcurrentUpdateError";
  }
}

function document(raw: string | null): QueueDocument {
  if (raw === null) return { version: 1, jobs: [], uploads: {}, pointers: {} };
  try {
    const parsed = JSON.parse(raw) as QueueDocument;
    if (
      parsed.version !== 1 ||
      !Array.isArray(parsed.jobs) ||
      !parsed.uploads ||
      typeof parsed.uploads !== "object" ||
      Array.isArray(parsed.uploads) ||
      !parsed.pointers ||
      typeof parsed.pointers !== "object" ||
      Array.isArray(parsed.pointers) ||
      !parsed.jobs.every(
        (job) =>
          job && typeof job === "object" && typeof job.jobId === "string",
      ) ||
      new Set(parsed.jobs.map((job) => job.jobId)).size !== parsed.jobs.length
    )
      throw new Error();
    return parsed;
  } catch {
    throw new Error(
      "The saved media queue is invalid. Restore its original local state before retrying.",
    );
  }
}

function entry(queue: QueueDocument, id: string): string {
  return JSON.stringify([
    queue.jobs.find((job) => job.jobId === id),
    Object.hasOwn(queue.uploads, id) ? queue.uploads[id] : undefined,
    Object.hasOwn(queue.pointers, id) ? queue.pointers[id] : undefined,
  ]);
}

/** Merge unrelated jobs. A conflicting update to the same job must restart from durable state. */
function merge(
  before: QueueDocument,
  desired: QueueDocument,
  current: QueueDocument,
  activeJobId?: string,
): QueueDocument {
  const jobs = new Map(current.jobs.map((job) => [job.jobId, job]));
  const uploads = new Map(Object.entries(current.uploads));
  const pointers = new Map(Object.entries(current.pointers));
  const ids = new Set(
    [...before.jobs, ...desired.jobs].map((job) => job.jobId),
  );
  if (activeJobId) ids.add(activeJobId);
  for (const id of ids) {
    const oldValue = entry(before, id);
    const nextValue = entry(desired, id);
    if (oldValue === nextValue && id !== activeJobId) continue;
    const currentValue = entry(current, id);
    if (currentValue !== oldValue && currentValue !== nextValue)
      throw new MediaQueueConcurrentUpdateError();
    if (oldValue === nextValue) continue;
    const job = desired.jobs.find((candidate) => candidate.jobId === id);
    if (job) jobs.set(id, job);
    else jobs.delete(id);
    if (job && Object.hasOwn(desired.uploads, id))
      uploads.set(id, desired.uploads[id]);
    else uploads.delete(id);
    if (job && Object.hasOwn(desired.pointers, id))
      pointers.set(id, desired.pointers[id]);
    else pointers.delete(id);
  }
  return {
    version: 1,
    jobs: [...jobs.values()],
    uploads: Object.fromEntries(uploads),
    pointers: Object.fromEntries(pointers),
  };
}

/** The backing store owns exclusion. Snapshots identify each caller's intended changes only. */
export class MediaQueuePersistence {
  private readonly snapshots = new WeakMap<object, string | null>();

  constructor(
    private readonly storage: SignalProtocolLocalStore,
    private readonly key: string,
  ) {}

  capture(state: object, raw: string | null): void {
    this.snapshots.set(state, raw);
  }

  async save(
    state: object,
    desiredRaw: string,
    maxJobs: number,
    activeJobId?: string,
    maxPreparedUploadBytes?: number,
  ): Promise<void> {
    if (!this.snapshots.has(state))
      throw new Error("The media queue has no durable write snapshot.");
    const before = document(this.snapshots.get(state)!);
    const desired = document(desiredRaw);
    for (let attempt = 0; attempt < 16; attempt++) {
      const currentRaw = await this.storage.getMetadata(this.key);
      const current = document(currentRaw);
      const merged = merge(before, desired, current, activeJobId);
      if (merged.jobs.length > maxJobs)
        throw new Error(
          "The media queue is full. Complete existing jobs before adding work.",
        );
      if (maxPreparedUploadBytes !== undefined)
        assertQueuedUploadCapacity(
          current.uploads,
          merged.uploads,
          maxPreparedUploadBytes,
        );
      const mergedRaw = JSON.stringify(merged);
      try {
        if (
          await this.storage.compareAndSetMetadata(
            this.key,
            currentRaw,
            mergedRaw,
          )
        ) {
          this.capture(state, desiredRaw);
          return;
        }
      } catch (error) {
        // A lost local response can follow a durable write. Retain only observed progress.
        try {
          if ((await this.storage.getMetadata(this.key)) === mergedRaw)
            this.capture(state, desiredRaw);
        } catch {
          /* The original write error remains authoritative. */
        }
        throw error;
      }
    }
    throw new MediaQueueConcurrentUpdateError();
  }
}
