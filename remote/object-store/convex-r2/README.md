# Convex R2 Object Store

This subpath is a client adapter for application-owned Convex functions backed
by the `@convex-dev/r2` component. It is not the component and does not own the
application's bucket, credentials, schema, authorization, or metadata model.

## Why it exists

The Convex client calls generated function references, while `@convex-dev/r2`
operates inside the application backend. This adapter maps that generated API
to `SignalProtocolRemoteObjectStore` without moving storage policy, provider keys, or
component ownership into the SDK.

## Setup

The application supplies a Convex client and generated function references.
The adapter loads no Convex runtime dependency. The application installs and
mounts the `@convex-dev/r2` component in its own backend.

## Client usage

<!-- doc-snippet:skip requires-external-context -->
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

## Broker contract

The application supplies the four Convex functions. Their types follow
`ConvexR2ObjectStoreApi`:

- `createUpload` is a mutation that reserves an upload for the authenticated caller.
- `createDownload` is an action that returns a short-lived download operation.
- `completeUpload` is an action that validates provider metadata before completion.
- `deleteObject` is a mutation that authorizes and records deletion.

The broker owns the `requestId -> objectId -> providerKey` mapping. It scopes
retry identifiers to the authenticated caller and returns stable object IDs for
retries. It checks the reserved ciphertext size and content type before marking
an upload complete. Provider credentials and keys stay on the backend.

The published SDK supplies the client adapter and its types. The application
supplies the broker implementation. If the application must confirm physical
removal, it tracks provider deletion.

See the [object-store guide](../README.md) and
[remote guide](../../README.md).
