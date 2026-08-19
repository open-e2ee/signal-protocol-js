# Integration Interfaces

> [README](../README.md) | [Architecture](../ARCHITECTURE.md) |
> [Adapters](../ADAPTERS.md)

The Signal Protocol SDK keeps platform and backend infrastructure behind
explicit TypeScript interfaces. The client owns protocol coordination. The host
application owns persistence, authentication, authorization, and product
policy.

## Boundary map

```text
SignalProtocolClient
├── ISignalProtocolLocalStore        device-local protocol state
├── ISignalProtocolRelayServer       authenticated device, prekey, and envelope service
├── SignalProtocolRemoteObjectStore  brokered encrypted-object operations (optional)
├── media callbacks          application-owned attachment bytes and caches
└── lifecycle hooks          application reactions and observability

Local-store bootstrap
└── ISignalProtocolLocalSecretVault  small platform-managed bootstrap secrets
```

The interfaces are public contracts, but they do not make an implementation
secure by themselves. Each adapter must preserve the ownership and atomicity
requirements described below.

## `ISignalProtocolLocalStore`

`ISignalProtocolLocalStore` persists the current device's identities, prekeys, sessions,
sender keys, contact trust, retry records, and operational metadata.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { ISignalProtocolLocalStore } from "@open-e2ee/signal-protocol-sdk/local/store";
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";

const storage: ISignalProtocolLocalStore = appProtocolStore;

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

A production implementation must:

- preserve compare-and-swap and transaction semantics for trust and session
  transitions.
- consume one-time prekeys atomically with the corresponding session commit.
- persist exact device/session ownership metadata.
- treat account reset as a coordinated lifecycle across protocol records,
  bootstrap secrets, backups, and application state.
- avoid placing decrypted application messages in the protocol store.

The [local-store guide](../local/store/README.md) lists the available adapters
and their status.

## `ISignalProtocolLocalSecretVault`

`ISignalProtocolLocalSecretVault` is a deliberately small interface for bootstrap
secrets that must live outside the main local store, such as a database
encryption key.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { ISignalProtocolLocalSecretVault } from "@open-e2ee/signal-protocol-sdk";

const vault: ISignalProtocolLocalSecretVault = {
  getSecret: (name) => platformSecrets.getBytes(name),
  setSecret: (name, value) => platformSecrets.setBytes(name, value),
  deleteSecret: (name) => platformSecrets.delete(name),
};
```

It is not a second general-purpose protocol database. Backup, biometric access,
device migration, uninstall persistence, and deletion behavior depend on the
selected platform service and host configuration. See the
[secret-vault guide](../local/vault/README.md).

## `ISignalProtocolRelayServer`

`ISignalProtocolRelayServer` represents the authenticated application backend used for
device registration, account identity state, public prekeys, encrypted-envelope
delivery, provisioning, key rotation, and encrypted group coordination.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { ISignalProtocolRelayServer } from "@open-e2ee/signal-protocol-sdk/remote/relay";
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;

const relay: ISignalProtocolRelayServer = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});
```

The application backend must:

- authenticate every caller
- derive ownership from trusted server context
- authorize reads and writes
- atomically consume one-time prekeys
- allocate linked-device identifiers
- apply retention and abuse controls

A client-supplied user identifier is a routing input, not proof of identity.

The relay stores public protocol material, ciphertext, and required routing
metadata. It must not require device private keys or decrypted message content.
See the [relay guide](../remote/relay/README.md).

## `SignalProtocolRemoteObjectStore`

`SignalProtocolRemoteObjectStore` supplies short-lived upload and download operations
for already encrypted objects. It is provider-neutral and optional.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type {
  SignalProtocolRemoteObjectStore,
} from "@open-e2ee/signal-protocol-sdk/remote/object-store";

const remoteObjectStore: SignalProtocolRemoteObjectStore = {
  createUpload: (request) => appObjectBroker.createUpload(request),
  createDownload: (request) => appObjectBroker.createDownload(request),
  completeUpload: (request) => appObjectBroker.completeUpload(request),
  deleteObject: (request) => appObjectBroker.deleteObject(request),
};
```

The broker owns the mapping:

```text
authenticated principal + retry requestId
  -> canonical objectId
  -> private provider key
```

It must:

- keep provider credentials and keys off the client
- enforce ciphertext size and content-type policy
- make upload completion idempotent
- authorize every download and deletion

See the [remote object-store guide](../remote/object-store/README.md).

## Application callbacks

Application content remains outside the infrastructure adapters. Configure
media lifecycle callbacks and client hooks at the client boundary:

<!-- doc-snippet:skip requires-external-context -->
```ts
const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay, remoteObjectStore },
  media: {
    loadLocalAttachment: ({ localMediaId }) =>
      appDrafts.readBytes(localMediaId),
    saveUploadedAttachment: ({ localMediaId, attachment }) =>
      appPointers.save(localMediaId, attachment),
    saveDownloadedAttachment: ({ attachmentId, downloaded }) =>
      appMediaCache.save(attachmentId, downloaded.data),
    deleteLocalAttachment: ({ attachmentId }) =>
      appMediaCache.delete(attachmentId),
  },
  hooks: {
    onMessageDecrypted: (message) => appMessages.accept(message),
    onDecryptionError: (sessionId, error) =>
      appObservability.recordDecryptionFailure(sessionId, error),
  },
});
```

Callbacks may update application databases, caches, UI state, and telemetry.
Never treat them as a transactional extension of a completed protocol state
update, unless the specific API says so.

## Choosing an integration

- Use an included adapter when its platform and ownership model match the
  application.
- Implement the public interface when infrastructure requirements differ.
- Import provider and platform adapters from explicit package subpaths so
  unrelated dependencies stay out of client bundles.
- Keep authentication and product authorization in the application backend,
  even when an SDK helper supplies generic broker mechanics.

See [client composition](./CLIENT_COMPOSITION.md) for the complete client
configuration shape and [documentation standards](./DOCUMENTATION_STANDARDS.md)
for comment and guide conventions.
