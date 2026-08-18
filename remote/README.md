# Remote Guide

> Infrastructure | Implements `ISignalProtocolRelayServer` and `SignalProtocolRemoteObjectStore` | [Architecture](../ARCHITECTURE.md)

The backend layer is responsible for server-owned protocol state: public
prekeys, device registration, encrypted-envelope delivery, and provisioning
support.

## Why it exists

Signal Protocol protects message content but does not provide account
authentication, device discovery, mailbox delivery, or a remote object store.
Explicit relay and object-store contracts keep those application services
replaceable and prevent them from owning private keys or plaintext.

## Supported Implementations

### Relay

- `ConvexSignalProtocolRelayServer` from `@open-e2ee/signal-protocol-sdk/remote/relay/convex`
- `InMemorySignalProtocolRelayServer` from `@open-e2ee/signal-protocol-sdk/remote/relay/memory`
- custom implementations via `ISignalProtocolRelayServer`

### Remote object store

- `ConvexR2ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `S3ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- custom implementations via `SignalProtocolRemoteObjectStore`

## Composition

```ts
import { SignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  ConvexSignalProtocolRelayServer,
  type ConvexSignalProtocolRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { ExpoSignalProtocolStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;

const signal = await SignalProtocolClient.create(userId, {
  storage: new ExpoSignalProtocolStore(),
  relay: new ConvexSignalProtocolRelayServer(convex, signalApi, {
    currentUserId: userId,
  }),
});
```

## Relay Responsibilities

An `ISignalProtocolRelayServer` implementation must preserve the package’s protocol semantics for:

- identity and prekey upload
- prekey bundle fetch
- device registration and listing
- envelope delivery
- linked-device provisioning state
- stale-device and unlink cleanup

## Security Invariants

### One-time-prekey semantics

Bundle fetch must preserve one-time-prekey consumption semantics for concurrent callers. The relay must not hand out the same one-time prekey as if it were still unused.

### Device ownership

- the server owns linked-device slot allocation
- clients must not choose linked `deviceId`s
- unlink and stale cleanup must stay consistent across active identity types

### Public-key access

- readers need public-key access for session establishment
- writers must only mutate their own account/device state

## Remote Object Store

`SignalProtocolRemoteObjectStore` is optional and only needed for encrypted attachment/file flows.

In practice, attachment and encrypted file support is a common consumer path,
so give object-store adapters the same standing as relay adapters.

The port is deliberately brokered. An authenticated application backend maps a
retry-stable `requestId` to a canonical `objectId` and a private provider key,
then issues short-lived upload and download operations. Cloud credentials and
unrestricted provider clients do not belong in the app runtime.

### Convex R2

`ConvexR2ObjectStore` is a client adapter, not a Convex component. The
application installs, mounts, and configures `@convex-dev/r2`, owns the R2
bucket and credentials, and exposes authenticated app-owned functions for
create, download, completion, and deletion.

```ts
import { SignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { api } from "../convex/_generated/api";

const signal = await SignalProtocolClient.create(userId, {
  storage,
  relay,
  remoteObjectStore: convexR2ObjectStore({
    convex,
    api: api.signalObjectStore,
  }),
});
```

The adapter accepts the generated module directly. The functions
`createDownload` and `completeUpload` are actions, because they produce
time-sensitive credentials or await provider metadata. The functions
`createUpload` and `deleteObject` are mutations.

The optional server entry point removes repetitive broker plumbing without
taking ownership away from the application:

```ts
// convex/signalObjectStore.ts
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

The application defines the referenced internal functions in
`convex/signalObjectStoreModel.ts`:

- `reserve` authenticates the caller and idempotently persists
  `requestId -> objectId -> providerKey`.
- `resolve` authorizes `download` or `complete` and returns the provider key
  plus the reserved content type and length.
- `complete` re-authorizes the caller and idempotently marks an upload complete
  after the helper verifies synchronized R2 metadata. The action needs this
  second authorization because its query and mutation are separate
  transactions.
- `remove` authorizes deletion and records the logical removal. It returns the
  stable provider key, so the caller can schedule component deletion
  transactionally.

The helper supplies public validators and extracts expiry from the actual
Signature Version 4 URLs. It verifies uploaded size and content type, and it
calls the R2 component with the correct Convex contexts. It has no runtime
import of `@convex-dev/r2`. S3-only consumers do not load the component.

### Amazon S3 and S3-compatible storage

`S3ObjectStore` is framework-neutral. Supply an authenticated backend broker
that creates presigned operations. AWS SDK clients and AWS credentials remain
on that backend. The broker follows the same identity contract: it receives a
retry-stable `requestId`, reserves the private provider key, and returns the
canonical `objectId`.

```ts
import { s3ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/s3";

const remoteObjectStore = s3ObjectStore({
  broker: {
    createUpload: (input) => storageApi.createS3Upload(input),
    createDownload: (input) => storageApi.createS3Download(input),
    completeUpload: (input) => storageApi.completeS3Upload(input),
    deleteObject: (input) => storageApi.deleteS3Object(input),
  },
});
```

Every remote object store should receive only ciphertext plus the metadata
needed to authorize and construct short-lived operations.

## Local development

Use `InMemorySignalProtocolRelayServer` when multiple clients need a shared in-memory relay:

```ts
import { SignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { InMemorySignalProtocolRelayServer } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";
import { InMemorySignalProtocolStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const relay = new InMemorySignalProtocolRelayServer();

const alice = await SignalProtocolClient.create("alice", {
  storage: new InMemorySignalProtocolStore(),
  relay,
});

const bob = await SignalProtocolClient.create("bob", {
  storage: new InMemorySignalProtocolStore(),
  relay,
});
```

## Related Docs

- [README](../README.md)
- [ADAPTERS](../ADAPTERS.md)
- [local/store/README.md](../local/store/README.md)
- [Relay Guide](./relay/README.md)
- [Object Store Guide](./object-store/README.md)
