# Convex R2 Object Store

This subpath is a client adapter for application-owned Convex functions backed
by the `@convex-dev/r2` component. It is not the component and does not own the
application's bucket, credentials, schema, authorization, or metadata model.

## Why it exists

The Convex client calls generated function references, while `@convex-dev/r2`
operates inside the application backend. This adapter maps that generated API
to `SignalProtocolRemoteObjectStore` without moving storage policy, provider keys, or
component ownership into the SDK.

## Client usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { api } from "../convex/_generated/api";

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    storage,
    relay,
    remoteObjectStore: convexR2ObjectStore({
      convex,
      api: api.signalObjectStore,
    }),
  },
});
```

`api.signalObjectStore` must expose `createUpload`, `createDownload`,
`completeUpload`, and `deleteObject` with the function kinds and values defined
by `ConvexR2ObjectStoreApi`.

## Optional server helper

The server-only subpath supplies validators and broker mechanics while keeping
authorization and persistence in application callbacks:

```ts
import { R2 } from "@convex-dev/r2";
import {
  defineConvexR2ObjectStore,
  type ConvexR2ObjectCallbacks,
} from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server";
import { components, internal } from "./_generated/api";

const objects =
  internal.signalObjectStoreModel satisfies ConvexR2ObjectCallbacks;

export const {
  createUpload,
  createDownload,
  completeUpload,
  deleteObject,
} = defineConvexR2ObjectStore({
  r2: new R2(components.r2),
  limits: {
    maxContentLength: 50 * 1024 * 1024,
    allowedContentTypes: ["application/octet-stream"],
    downloadExpiresInSeconds: 15 * 60,
  },
  objects,
});
```

The callbacks must authenticate and authorize each operation and persist the
`requestId -> objectId -> providerKey` mapping. The helper derives expiry from
the actual signed operation and synchronizes provider metadata in an action. It
also checks the reserved content type and byte length before completion.

Deletion is asynchronous at the provider boundary. The public mutation
atomically records the application removal and asks the R2 component to schedule
its retried deletion action. Applications that need confirmed physical removal
must track that completion separately.

The server helper uses structural types and does not import
`@convex-dev/r2` at runtime. Consumers that use only S3 do not load that
component.

See the [object-store guide](../README.md) and
[remote guide](../../README.md).
