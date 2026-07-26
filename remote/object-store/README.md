# Remote Object Store

`SignalProtocolRemoteObjectStore` is the provider-neutral client contract for uploading,
downloading, completing, and deleting encrypted byte objects through
short-lived backend-brokered operations.

## Why it exists

Attachments are too large for normal encrypted messages. A host backend must
authorize access and issue narrow storage operations without exposing cloud
credentials or provider keys to the app runtime.

The identity chain is:

```text
retry-stable requestId -> canonical objectId -> private provider key
```

## Custom broker usage

```ts
import type {
  SignalProtocolRemoteObjectStore,
} from "@open-e2ee/signal-protocol-sdk/remote/object-store";

const remoteObjectStore: SignalProtocolRemoteObjectStore = {
  createUpload: (request) => appStorageApi.createUpload(request),
  createDownload: (request) => appStorageApi.createDownload(request),
  completeUpload: (request) => appStorageApi.completeUpload(request),
  deleteObject: (request) => appStorageApi.deleteObject(request),
};
```

The backend must scope `requestId` to the authenticated principal, return the
same reservation for retries, generate the canonical `objectId`, keep the
provider key private, enforce size/content-type policy, and authorize every
download, completion, and deletion.

Provider adapters:

- [Convex R2](./convex-r2/README.md)
- [Amazon S3 and compatible brokers](./s3/README.md)

See the [media guide](../../media/README.md) and
[API reference](../../docs/api/README.md).
