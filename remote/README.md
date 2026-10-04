# Remote Guide

> Infrastructure | Implements `SignalProtocolRelayServer` and `SignalProtocolRemoteObjectStore` | [Architecture](../ARCHITECTURE.md)

The remote modules contain client adapters and transport contracts for public
prekeys, device registration, encrypted envelopes, and encrypted objects.
The published package excludes relay and object-store server implementations.

## Why it exists

Signal Protocol protects message content but does not provide account
authentication, device discovery, mailbox delivery, or a remote object store.
Explicit relay and object-store contracts keep those application services
replaceable and prevent them from owning private keys or plaintext.

## Supported Implementations

### Relay

- the OpenE2EE Signal Protocol Relay through `createHostedSignalProtocolClient()` from the package root
- custom client transports via `SignalProtocolRelayServer`

### Remote object store

- `ConvexR2ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `S3ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- custom implementations via `SignalProtocolRemoteObjectStore`

## Composition

<!-- doc-snippet:skip requires-production-adapters -->
```ts
import { createHostedSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";

const signal = await createHostedSignalProtocolClient({
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: await expoStore(),
  },
  hosted: {
    // The environment-scoped connection URL from the OpenE2EE console.
    relayUrl: process.env.EXPO_PUBLIC_OPEN_E2EE_RELAY_URL!,
    // Returns a short-lived signed assertion for the signed-in user.
    getIdentityAssertion,
  },
});
```

## Relay Responsibilities

An `SignalProtocolRelayServer` implementation must preserve the package’s protocol semantics for:

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

<!-- doc-snippet:skip requires-external-context -->
```ts
import { DefaultSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { api } from "../convex/_generated/api";

const signal = await DefaultSignalProtocolClient.create(userId, {
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

The application supplies these broker functions. Each function authenticates
and authorizes its caller. The broker owns idempotent reservations, object
metadata, provider keys, and completion checks. See the
[Convex R2 client contract](./object-store/convex-r2/README.md).

### Amazon S3 and S3-compatible storage

`S3ObjectStore` is framework-neutral. Supply an authenticated backend broker
that creates presigned operations. AWS SDK clients and AWS credentials remain
on that backend. The broker follows the same identity contract: it receives a
retry-stable `requestId`, reserves the private provider key, and returns the
canonical `objectId`.

<!-- doc-snippet:skip requires-external-context -->
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

## Sandbox development

Use a Sandbox connection URL from the OpenE2EE console with
`createHostedSignalProtocolClient()`. Supply the same identity-assertion callback
and device-local store that your application uses for production.

## Related Docs

- [README](../README.md)
- [ADAPTERS](../ADAPTERS.md)
- [local/store/README.md](../local/store/README.md)
- [Relay Guide](./relay/README.md)
- [Object Store Guide](./object-store/README.md)
