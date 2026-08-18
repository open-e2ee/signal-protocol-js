/**
 * Request for a short-lived, direct object upload operation.
 *
 * `requestId` is an idempotency key for one logical upload. It is not an
 * object identifier or a provider key. An authenticated backend maps it to a
 * stable canonical object identifier and a private provider key.
 */
export type RemoteObjectUploadRequest = {
  /**
   * Stable idempotency key for retries of one logical upload.
   *
   * The backend must scope this untrusted value to the authenticated principal
   * and return the same object reservation when the caller retries the request.
   */
  requestId: string;
  /** MIME type of the encrypted bytes in the upload. */
  contentType: string;
  /** Exact encrypted object length in bytes. */
  contentLength: number;
};

/** Short-lived credentials for a direct object upload. */
export interface RemoteObjectUpload {
  /** Canonical opaque identifier assigned to the uploaded object. */
  objectId: string;
  /** Short-lived upload URL issued by the application's storage broker. */
  uploadUrl: string;
  /** Unix timestamp in milliseconds when the upload operation expires. */
  expiresAt: number;
  /** Request headers that must accompany the upload. */
  headers?: Record<string, string>;
  /** Upload protocol. Direct PUT applies when omitted. */
  protocol?: 'put' | 'tus';
}

/** Request for a short-lived, direct object download operation. */
export type RemoteObjectDownloadRequest = {
  /** Opaque identifier from an encrypted attachment pointer. */
  objectId: string;
};

/** Short-lived credentials for a direct object download. */
export interface RemoteObjectDownload {
  /** Short-lived download URL issued by the application's storage broker. */
  downloadUrl: string;
  /** Unix timestamp in milliseconds when the download operation expires. */
  expiresAt: number;
  /** Request headers that must accompany the download. */
  headers?: Record<string, string>;
}

/** Notification that a direct upload completed successfully. */
export type RemoteObjectCompleteUploadRequest = {
  /** Canonical opaque identifier returned by `createUpload()`. */
  objectId: string;
};

/** Request to delete a remote encrypted object. */
export type RemoteObjectDeleteRequest = {
  /** Opaque identifier of the object to delete. */
  objectId: string;
};

/**
 * Brokered remote storage for encrypted byte objects.
 *
 * Implementations request narrowly scoped, short-lived operations from an
 * authenticated application backend. Cloud credentials and unrestricted
 * storage clients must never reach an app runtime.
 */
export interface SignalProtocolRemoteObjectStore {
  /** Create a short-lived direct upload operation. */
  createUpload(input: RemoteObjectUploadRequest): Promise<RemoteObjectUpload>;

  /** Create a short-lived direct download operation. */
  createDownload(input: RemoteObjectDownloadRequest): Promise<RemoteObjectDownload>;

  /**
   * Finalize provider metadata after a successful upload, when required.
   *
   * Implementations must make this operation idempotent because a client may
   * retry it after an interrupted upload workflow.
   */
  completeUpload?(input: RemoteObjectCompleteUploadRequest): Promise<void>;

  /** Delete an encrypted object, when supported by the backend. */
  deleteObject?(input: RemoteObjectDeleteRequest): Promise<void>;
}
