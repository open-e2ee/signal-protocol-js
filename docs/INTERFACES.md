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
├── SignalProtocolLocalStore        device-local protocol state
├── SignalProtocolRelayServer       authenticated device, prekey, and envelope service
├── SignalProtocolRemoteObjectStore  brokered encrypted-object operations (optional)
├── media callbacks          application-owned attachment bytes and caches
└── lifecycle hooks          application reactions and observability

Local-store bootstrap
└── SignalProtocolLocalSecretVault  small platform-managed bootstrap secrets
```

The interfaces are public contracts, but they do not make an implementation
secure by themselves. Each adapter must preserve the ownership and atomicity
requirements described below.

## `SignalProtocolLocalStore`

`SignalProtocolLocalStore` persists the current device's identities, prekeys, sessions,
sender keys, contact trust, retry records, and operational metadata.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { SignalProtocolLocalStore } from "@open-e2ee/signal-protocol-sdk/local/store";
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";

const storage: SignalProtocolLocalStore = appProtocolStore;

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

## `SignalProtocolLocalSecretVault`

`SignalProtocolLocalSecretVault` is a deliberately small interface for bootstrap
secrets that must live outside the main local store, such as a database
encryption key.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { SignalProtocolLocalSecretVault } from "@open-e2ee/signal-protocol-sdk";

const vault: SignalProtocolLocalSecretVault = {
  getSecret: (name) => platformSecrets.getBytes(name),
  setSecret: (name, value) => platformSecrets.setBytes(name, value),
  deleteSecret: (name) => platformSecrets.delete(name),
};
```

It is not a second general-purpose protocol database. Backup, biometric access,
device migration, uninstall persistence, and deletion behavior depend on the
selected platform service and host configuration. See the
[secret-vault guide](../local/vault/README.md).

## `SignalProtocolRelayServer`

`SignalProtocolRelayServer` represents the authenticated application backend used for
device registration, account identity state, public prekeys, encrypted-envelope
delivery, provisioning, key rotation, and encrypted group coordination.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { SignalProtocolRelayServer } from "@open-e2ee/signal-protocol-sdk/remote/relay";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";

// Development uses the in-memory relay. Production connects to the OpenE2EE
// Signal Protocol Relay through `createHostedSignalProtocolClient()`, or to an
// application backend that implements this interface.
const relay: SignalProtocolRelayServer = inMemoryRelay();
```

The application backend must:

- authenticate every caller
- derive ownership from trusted server context
- authorize reads and writes
- atomically consume one-time prekeys
- allocate linked-device identifiers
- apply retention and abuse controls

A client-supplied user identifier is a routing input, not proof of identity.

Each adapter implements `getPreKeyInventory` for prekey synchronization.
It returns both reusable-key metadata records and both one-time-key counts.
These observations do not consume keys, reserve a version, or authorize an upload.
Callers request new observations after intervening work.
The Signal Protocol Relay persists a separate public-eligibility snapshot for its published
prekeys. A publication reads the current public inventory, names its exact
predecessor revision, persists one pending receipt before the request, and reads
the accepted inventory before it commits the new receipt. An exact retry can
recover a lost response. A stale or reordered writer cannot restore material
that the Relay already issued. Retained private prekeys are not a publication
inventory.

The server remains responsible for atomic one-time-key consumption.

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
    preparedUploads: appPreparedUploads,
    maxPreparedUploadBytes: appUploadBudgetBytes,
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
