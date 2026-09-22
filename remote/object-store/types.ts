/**
 * Request for a short-lived, direct object upload operation.
 *
 * `requestId` and `preparedAt` identify one immutable preparation. Neither is an
 * object identifier or a provider key. An authenticated backend maps it to a
 * stable canonical object identifier and a private provider key.
 */
export type RemoteObjectUploadRequest = {
  /**
   * Stable nonce for retries of one logical upload.
   *
   * The backend must scope this untrusted value to the authenticated principal
   * and preparation time. Exact retries return the same object reservation.
   */
  requestId: string;
  /** Immutable preparation time in Unix milliseconds. Never refresh it for a retry. */
  preparedAt: number;
  /** MIME type of the encrypted bytes in the upload. */
  contentType: string;
  /** Exact encrypted object length in bytes. */
  contentLength: number;
  /** SHA-256 digest of the exact encrypted bytes. */
  digest: Uint8Array;
  /** Optional broker read-capability commitment. Required by the Signal Protocol Relay. */
  readCapabilityDigest?: Uint8Array;
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
  protocol?: "put" | "tus";
}

/** Request for a short-lived, direct object download operation. */
export type RemoteObjectDownloadRequest = {
  /** Opaque identifier from an encrypted attachment pointer. */
  objectId: string;
  /** Read authority carried inside the encrypted pointer, never in a URL. */
  readCapability?: string;
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

/** Broker-verified bytes stored under the original upload authorization. */
export interface RemoteObjectUploadReceipt {
  objectId: string;
  contentLength: number;
  /** SHA-256 verified against stored bytes independently of caller metadata. */
  digest: Uint8Array;
}

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

  /**
   * Refuse the original upload identity and delete its accepted object, if present.
   * Never create an upload to find it. Preserve accepted accounting. Resolve only
   * after durable refusal owns cleanup. A repeated request must be safe.
   */
  abandonUpload?(
    input: Pick<RemoteObjectUploadRequest, "requestId" | "preparedAt">,
  ): Promise<void>;

  /** Create a short-lived direct download operation. */
  createDownload(
    input: RemoteObjectDownloadRequest,
  ): Promise<RemoteObjectDownload>;

  /**
   * Finalize provider metadata after a successful upload, when required.
   *
   * Implementations must make this operation idempotent because a client may
   * retry it after an interrupted upload workflow.
   */
  completeUpload?(input: RemoteObjectCompleteUploadRequest): Promise<void>;

  /**
   * Recover an uncertain transfer using the original authorized object.
   *
   * Return a receipt only after verifying stored bytes and completing the
   * backend's acceptance transition. Return null only when bytes are absent
   * and the original authorization remains valid. Throw on unknown outcomes,
   * mismatch, deletion, or expiry. Never reserve another object here.
   * Omit this capability when the backend cannot provide that proof.
   */
  reconcileUpload?(
    input: RemoteObjectCompleteUploadRequest,
  ): Promise<RemoteObjectUploadReceipt | null>;

  /** Delete an encrypted object, when supported by the backend. */
  deleteObject?(input: RemoteObjectDeleteRequest): Promise<void>;
}
