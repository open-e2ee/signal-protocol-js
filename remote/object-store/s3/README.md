# S3 Object Store

The S3 adapter connects `SignalProtocolRemoteObjectStore` to an application-owned
broker for Amazon S3 or a compatible object-storage service.

## Why it exists

AWS SDK clients and cloud credentials belong on an authenticated backend, not
in the app runtime. The adapter consumes only the short-lived operations
returned by that backend.

## Usage

<!-- doc-snippet:skip requires-external-context -->
```ts
import { s3ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/s3";

const remoteObjectStore = s3ObjectStore({
  broker: {
    createUpload: (input) => appStorageApi.createS3Upload(input),
    createDownload: (input) => appStorageApi.createS3Download(input),
    completeUpload: (input) => appStorageApi.completeS3Upload(input),
    reconcileUpload: (input) => appStorageApi.reconcileS3Upload(input),
    deleteObject: (input) => appStorageApi.deleteS3Object(input),
  },
});
```

The broker must:

- authenticate the caller
- make upload reservation idempotent
- generate opaque object identifiers and private provider keys
- restrict signed operations to the reserved key and expected method
- enforce content length and content type
- bind the exact ciphertext digest to each reservation

`reconcileUpload` is an optional backend capability for uncertain transfers.
It must authenticate the caller and verify stored bytes against the original reservation.
Return the object ID, exact length, and verified SHA-256 only after backend acceptance completes.
Return `null` only when bytes are absent and the original authorization remains valid.

Throw on unknown outcomes, mismatch, deletion, or expiry. Never create another reservation during reconciliation.
Omit this method when the backend checks only metadata or cannot verify stored bytes.

Bucket names, credentials, and unrestricted SDK clients must not cross into the
application client.

See the [object-store guide](../README.md) and
[media guide](../../../media/README.md).
