/**
 * Provider-neutral remote object storage contract.
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
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from './types';
