import type { FunctionReference } from 'convex/server';
import type { ConvexReactClient } from 'convex/react';
import type { ConvexHttpClient } from 'convex/browser';
import type {
  RemoteObjectCompleteUploadRequest,
  RemoteObjectDeleteRequest,
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadRequest,
  SignalRemoteObjectStore,
} from '../types';
import {
  normalizeDownload,
  normalizeUpload,
  validateObjectId,
  validateUploadRequest,
} from '../validation';

/** App-owned Convex functions that broker access to an `@convex-dev/r2` component. */
export interface ConvexR2ObjectStoreApi {
  /** Public mutation returning an object ID, upload URL, and actual expiry. */
  createUpload: FunctionReference<
    'mutation',
    'public',
    RemoteObjectUploadRequest,
    RemoteObjectUpload
  >;
  /** Public action returning fresh download credentials, or `null` when absent. */
  createDownload: FunctionReference<
    'action',
    'public',
    RemoteObjectDownloadRequest,
    RemoteObjectDownload | null
  >;
  /** Idempotent action that awaits metadata synchronization after an upload. */
  completeUpload: FunctionReference<
    'action',
    'public',
    RemoteObjectCompleteUploadRequest,
    null
  >;
  /** Idempotent mutation that logically removes the object and schedules R2 deletion. */
  deleteObject: FunctionReference<'mutation', 'public', RemoteObjectDeleteRequest, null>;
}

/** Convex client variants supported in app and background runtimes. */
export type ConvexObjectStoreClient = ConvexReactClient | ConvexHttpClient;

export interface ConvexR2ObjectStoreConfig {
  /** Authenticated Convex client used to call the app-owned broker functions. */
  convex: ConvexObjectStoreClient;
  /** References to the application's public storage broker functions. */
  api: ConvexR2ObjectStoreApi;
  /**
   * Client-side upload guard. The app-owned mutation must independently
   * enforce its authorization, object-key, content-type, and size policy.
   */
  maxSizeBytes?: number;
}

const DEFAULT_MAX_SIZE_BYTES = 50 * 1024 * 1024;

/**
 * Client adapter for application-owned Convex functions backed by
 * `@convex-dev/r2`.
 *
 * This package does not mount or configure the Convex component. The
 * application owns the component, authentication, authorization, and the
 * public wrapper functions represented by `ConvexR2ObjectStoreApi`.
 */
export class ConvexR2ObjectStore implements SignalRemoteObjectStore {
  private readonly convex: ConvexObjectStoreClient;
  private readonly api: ConvexR2ObjectStoreApi;
  private readonly maxSizeBytes: number;

  constructor(config: ConvexR2ObjectStoreConfig) {
    this.convex = config.convex;
    this.api = config.api;
    this.maxSizeBytes = config.maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;
    if (!Number.isSafeInteger(this.maxSizeBytes) || this.maxSizeBytes <= 0) {
      throw new RangeError('maxSizeBytes must be a positive safe integer');
    }
  }

  async createUpload(input: RemoteObjectUploadRequest): Promise<RemoteObjectUpload> {
    validateUploadRequest(input, this.maxSizeBytes);
    const result = await this.convex.mutation(this.api.createUpload, {
      requestId: input.requestId,
      contentType: input.contentType,
      contentLength: input.contentLength,
    });
    return normalizeUpload(result);
  }

  async createDownload(input: RemoteObjectDownloadRequest): Promise<RemoteObjectDownload> {
    validateObjectId(input.objectId);
    const result = await this.convex.action(this.api.createDownload, {
      objectId: input.objectId,
    });
    if (result === null) {
      throw new Error(`Remote object not found: ${input.objectId}`);
    }
    return normalizeDownload(result);
  }

  async completeUpload(input: RemoteObjectCompleteUploadRequest): Promise<void> {
    validateObjectId(input.objectId);
    await this.convex.action(this.api.completeUpload, {
      objectId: input.objectId,
    });
  }

  async deleteObject(input: RemoteObjectDeleteRequest): Promise<void> {
    validateObjectId(input.objectId);
    await this.convex.mutation(this.api.deleteObject, {
      objectId: input.objectId,
    });
  }
}
