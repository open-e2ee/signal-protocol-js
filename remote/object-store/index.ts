/**
 * Provider-neutral remote object store contract.
 *
 * Provider adapters are intentionally exported from explicit sibling paths:
 * `remote/object-store/convex-r2` and `remote/object-store/s3`.
 */
export type {
  RemoteObjectCompleteUploadRequest,
  RemoteObjectDeleteRequest,
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadReceipt,
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from "./types";
export {
  RemoteObjectUploadError,
  RemoteObjectUploadFailureCode,
} from "./upload-error";
export type { RemoteObjectUploadFailure } from "./upload-error";
