# Adapters Reference

> Navigation: [README](./README.md) | [ARCHITECTURE](./ARCHITECTURE.md) | [SECURITY](./docs/SECURITY.md) | **ADAPTERS**

`@open-e2ee/signal-protocol-sdk` uses explicit dependency injection for infrastructure. The package core does not assume a database, backend, or platform.

## Adapter Roles

### Relay: `ISignalProtocolRelayServer`

The relay interface handles server-owned Signal Protocol state:

- prekey upload and fetch
- device registration and device listing
- envelope delivery / message fanout
- linked-device provisioning support

Use:

- `ConvexSignalProtocolRelayServer` from `@open-e2ee/signal-protocol-sdk/remote/relay/convex`
- `MockSignalProtocolRelayServer` from `@open-e2ee/signal-protocol-sdk/remote/relay/mock`
- or a custom implementation

### Storage: `ISignalProtocolLocalStore`

The storage interface handles client-owned Signal Protocol state:

- account identity keys
- contact identities / TOFU
- prekeys
- sessions
- local message records and related metadata

Use:

- `ExpoSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/expo`
- Expo integration helpers like `getKeyStorage`, `getDatabaseKeyManager`, `clearDatabaseKeyCache`, and `createPreKeyMaintenanceStore` from `@open-e2ee/signal-protocol-sdk/local/store/expo`
- `IndexedDbSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web` (experimental)
- `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native` (experimental; use `await ReactNativeSignalProtocolStore.create({ storage })` with a caller-provided key-value backend)
- `NodeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/node`
- `MockSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/mock`
- or a custom implementation

### Remote object storage: `SignalProtocolRemoteObjectStore`

Optional encrypted file upload/download support for two-layer attachment encryption.

Use:

- `ConvexR2ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `defineConvexR2ObjectStore` from the server-only
  `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server` entry point
- `S3ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- or a custom implementation

Both concrete adapters call an authenticated application-backend broker. The
app runtime receives only narrowly scoped, short-lived operations; provider
credentials remain on the backend.

Upload requests carry a retry/idempotency `requestId`; the backend returns the
canonical `objectId` used in encrypted attachment pointers. Provider keys stay
private to the backend. The Convex server helper can supply generic validators,
R2 calls, expiry parsing, and metadata verification, while app-owned internal
functions retain authentication, authorization, and persistence.

## Composition

### Minimal local client

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const signal = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore() },
});
```

### Production client

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
const relay = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});

// Initialize the application-owned Expo/SQLCipher database bindings first.
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    storage: expoStore({ relay }),
    relay,
  },
});
```

See the [Expo storage guide](./local/store/expo/README.md) for the required
database and SQLCipher bootstrap.

### Local development with a shared relay

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const relay = mockRelay();

const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: mockStore(), relay },
});
```

## Security Expectations

### Relay implementations

- Prekey bundle fetch must preserve the package’s one-time-prekey semantics.
- Device registration, unlink, and stale cleanup must stay consistent across active identity types.
- Provisioning slot assignment is server-owned, not client-owned.
- Public-key reads and writes must enforce correct account ownership rules.

### Storage implementations

- Protect local key material at rest.
- Keep contact identity trust decisions stable and explicit.
- Persist linked-device identity state atomically enough that startup verification cannot enter a half-linked state.
- Preserve session record semantics; do not treat sessions as opaque blobs without honoring update and archive behavior.

## Choosing a Shape

Prefer these composition patterns:

- use `createSignalProtocolClient()` when app code owns identity, adapters, and protocol policy
- pass `storage` explicitly to every client composition
- pass `relay` only when you need sync, prekeys, or linked-device workflows
- keep `protocol.postQuantum` in product/security terms: `'required'` by default,
  `'compatible'` only for explicit non-PQ peer compatibility
- keep backend-specific code at integration boundaries, not in shared app logic
- keep platform storage imports on explicit subpaths, not the root package

## Custom Implementations

Use the public interfaces:

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import type { ISignalProtocolRelayServer } from "@open-e2ee/signal-protocol-sdk/remote/relay";
import type { SignalProtocolRemoteObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store";
import type { ISignalProtocolLocalStore } from "@open-e2ee/signal-protocol-sdk/local/store";
```

Then compose them through `createSignalProtocolClient()`:

```ts
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    storage: customStorage,
    relay: customRelay,
    remoteObjectStore: customObjectStorage,
  },
});
```

## Verifiable adapter design

Mock relay and storage adapters provide deterministic, in-memory behavior for
development environments. Production adapters remain dependency-injected so
applications can evaluate storage, delivery, and failure behavior without
reaching into client internals.

## Related Docs

- [README](./README.md)
- [Remote Guide](./remote/README.md)
- [Storage Guide](./local/store/README.md)
- [Client Guide](./client/README.md)
