import type {
  RemoteObjectCompleteUploadRequest,
  RemoteObjectDeleteRequest,
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from '../types';
import {
  normalizeDownload,
  normalizeUpload,
  validateObjectId,
  validateUploadRequest,
} from '../validation';

/**
 * Authenticated application-backend broker for Amazon S3 or a compatible
 * object store.
 *
 * Implement this interface in app integration code. Generate presigned
 * operations on the backend. Never ship AWS credentials in the app.
 */
export interface S3ObjectStoreBroker {
  /**
   * Reserve or recover one logical upload by `requestId`, returning the
   * backend-issued canonical `objectId` and a presigned provider operation.
   */
  createUpload(input: RemoteObjectUploadRequest): Promise<RemoteObjectUpload>;
  createDownload(input: RemoteObjectDownloadRequest): Promise<RemoteObjectDownload | null>;
  completeUpload?(input: RemoteObjectCompleteUploadRequest): Promise<void>;
  deleteObject(input: RemoteObjectDeleteRequest): Promise<void>;
}

export interface S3ObjectStoreConfig {
  /** Authenticated application-backend broker for presigned S3 operations. */
  broker: S3ObjectStoreBroker;
  /**
   * Client-side upload guard. The backend broker and bucket policy must
   * independently enforce authorization and upload constraints.
   */
  maxSizeBytes?: number;
}

const DEFAULT_MAX_SIZE_BYTES = 50 * 1024 * 1024;

/**
 * Framework-neutral client adapter for brokered, presigned S3 operations.
 *
 * The adapter validates broker responses and exposes the provider-neutral
 * `SignalProtocolRemoteObjectStore` contract. AWS SDKs and AWS credentials belong in
 * the authenticated backend that implements `S3ObjectStoreBroker`.
 */
export class S3ObjectStore implements SignalProtocolRemoteObjectStore {
  private readonly broker: S3ObjectStoreBroker;
  private readonly maxSizeBytes: number;

  constructor(config: S3ObjectStoreConfig) {
    this.broker = config.broker;
    this.maxSizeBytes = config.maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;
    if (!Number.isSafeInteger(this.maxSizeBytes) || this.maxSizeBytes <= 0) {
      throw new RangeError('maxSizeBytes must be a positive safe integer');
    }
  }

  async createUpload(input: RemoteObjectUploadRequest): Promise<RemoteObjectUpload> {
    validateUploadRequest(input, this.maxSizeBytes);
    return normalizeUpload(await this.broker.createUpload(input));
  }

  async createDownload(input: RemoteObjectDownloadRequest): Promise<RemoteObjectDownload> {
    validateObjectId(input.objectId);
    const result = await this.broker.createDownload(input);
    if (result === null) {
      throw new Error(`Remote object not found: ${input.objectId}`);
    }
    return normalizeDownload(result);
  }

  async completeUpload(input: RemoteObjectCompleteUploadRequest): Promise<void> {
    validateObjectId(input.objectId);
    await this.broker.completeUpload?.(input);
  }

  async deleteObject(input: RemoteObjectDeleteRequest): Promise<void> {
    validateObjectId(input.objectId);
    await this.broker.deleteObject(input);
  }
}
