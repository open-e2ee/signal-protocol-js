# Adapters Reference

> Navigation: [README](./README.md) | [ARCHITECTURE](./ARCHITECTURE.md) | [SECURITY](./docs/SECURITY.md) | **ADAPTERS**

`@open-e2ee/signal-protocol-sdk` uses explicit dependency injection for infrastructure. The package core does not assume a database, backend, or platform.

## Adapter Roles

### Relay: `SignalProtocolRelayServer`

The relay interface handles server-owned Signal Protocol state:

- prekey upload and fetch
- device registration and device listing
- envelope delivery / message fanout
- linked-device provisioning support

Use:

- the OpenE2EE Signal Protocol Relay through `createHostedSignalProtocolClient()` from the package root
- `InMemorySignalProtocolRelayServer` from `@open-e2ee/signal-protocol-sdk/remote/relay/memory`
- or a custom implementation

### Storage: `SignalProtocolLocalStore`

The storage interface handles client-owned Signal Protocol state:

- account identity keys
- contact identities / TOFU
- prekeys
- sessions
- local message records and related metadata

Use:

- `expoStore` and `ExpoSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/expo` (`await expoStore()` opens the SDK-owned SQLCipher database; `resetExpoStore` deletes it and opens an empty one; `createPreKeyMaintenanceStore` takes an open store)
- `reactNativeStore` and `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native` (bare React Native: `await reactNativeStore()` opens the SDK-owned SQLCipher database on op-sqlite with its key in the react-native-keychain vault; `resetReactNativeStore` deletes it and opens an empty one; `createPreKeyMaintenanceStore` takes an open store)
- `webSqliteStore` and `WebSqliteSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web-sqlite` (browsers: `await webSqliteStore()` opens the SDK-owned SQLite database in the origin private file system, encrypted in a Wasm worker; `resetWebSqliteStore` deletes it and opens an empty one; `createPreKeyMaintenanceStore` takes an open store; the page's Content Security Policy must allow `'wasm-unsafe-eval'`)
- `IndexedDbSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web` (browsers without the origin private file system, where `webSqliteStore` fails with `OPFS_UNAVAILABLE`)
- `KeyValueSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/key-value` (use `await KeyValueSignalProtocolStore.create({ storage, vault })` with a caller-provided key-value backend, verified with the exported backend-conformance kit, and a secret vault that holds the value key)
- `createRealmKeyValueBackend` from `@open-e2ee/signal-protocol-sdk/local/store/key-value/realm` (a key-value backend over an application-installed Realm)
- `createTransactionalKeyValueBackend` from `@open-e2ee/signal-protocol-sdk/local/store/key-value` (a key-value backend over another engine's transaction, through a synchronous `KeyValueTransaction` handle; the SDK applies each `atomicWrite` batch inside the transaction)
- `nodeStore` and `NodeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/node` (`await nodeStore({ directory, vault })` opens the SDK-owned SQLCipher database on the `better-sqlite3-multiple-ciphers` peer; `resetNodeStore` deletes it and opens an empty one; one process at a time owns the file; `createPreKeyMaintenanceStore` takes an open store)
- `InMemorySignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/memory`
- or a custom implementation

On React Native and Expo, the SDK reads random bytes only from the global `crypto.getRandomValues`. Install `react-native-get-random-values` 2.x or `react-native-quick-crypto`, and load it before the first SDK call. Without a global source, the SDK throws `SecureRandomUnavailableError`.

### Local secret vault: `SignalProtocolLocalSecretVault`

The device ID, the device-lifecycle state, the own profile key, and the value
key of the key-value store live in the vault that the application passes. The SDK does not choose a vault, and it
never writes these secrets to `localStorage`. A call without a vault throws an
`EncryptionError` with code `SECRET_VAULT_REQUIRED`.

Use:

- `ExpoSecureStoreSignalProtocolSecretVault` from `@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store`
- or a custom implementation

### Device metadata

The shared `./device` entries take platform metadata as an input and omit each
field that the application does not supply. These entries read it from the
platform:

- `@open-e2ee/signal-protocol-sdk/device/expo` (`react-native`, `expo-constants`, `expo-device`)
- `@open-e2ee/signal-protocol-sdk/device/react-native` (`react-native`, `react-native-device-info`)

### Remote object store: `SignalProtocolRemoteObjectStore`

Optional encrypted file upload/download support for two-layer attachment encryption.

Use:

- `ConvexR2ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `defineConvexR2ObjectStore` from the server-only
  `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server` entry point
- `S3ObjectStore` from `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- or a custom implementation

Both concrete adapters call an authenticated application-backend broker. The
app runtime receives only narrowly scoped, short-lived operations. Provider
credentials remain on the backend.

Upload requests carry a retry/idempotency `requestId`. The backend returns the
canonical `objectId` used in encrypted attachment pointers. Provider keys stay
private to the backend. The Convex server helper can supply generic validators,
R2 calls, expiry parsing, and metadata verification, while app-owned internal
functions retain authentication, authorization, and persistence.

### Local secret vault: `SignalProtocolLocalSecretVault`

Stores small bootstrap secrets, such as a database encryption key, in the
platform secret store, apart from the local store.

Use:

- `ExpoSecureStoreSignalProtocolSecretVault` from `@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store`
- `ReactNativeKeychainSignalProtocolSecretVault` from `@open-e2ee/signal-protocol-sdk/local/vault/react-native-keychain` (optional peer `react-native-keychain` 10.0.0 or later)
- `ElectronSafeStorageSignalProtocolSecretVault` from `@open-e2ee/signal-protocol-sdk/local/vault/electron-safe-storage`, in the Electron main process, with the app's `safeStorage`
- or a custom implementation

The Expo and React Native adapters keep the secret on this device. The Electron
adapter keeps only ciphertexts in a file that the app names, and the key that
decrypts them stays in the OS secret store. It fails closed on the Linux
`basic_text` backend. The react-native-keychain adapter
sets fixed options that the application cannot change: iOS
`AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`, Android `AES_GCM_NO_AUTH` storage at the
`SECURE_SOFTWARE` level, and no `cloudSync` key. react-native-keychain 10.0.0
turns iCloud sync on for any `cloudSync` value, `false` included
([issue #800](https://github.com/oblador/react-native-keychain/issues/800)).
The [secret-vault guide](./local/vault/README.md) gives the reason for each
option.

## Composition

### Minimal local client

<!-- doc-snippet:run adapters-local-client expect="" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const signal = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: inMemoryStore() },
});
```

### Production client

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

See the [Expo storage guide](./local/store/expo/README.md) for the required
database and SQLCipher bootstrap.

### Local development with a shared relay

<!-- doc-snippet:run adapters-shared-relay expect="" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const relay = inMemoryRelay();

const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: inMemoryStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: inMemoryStore(), relay },
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
- Preserve session record semantics. Do not treat sessions as opaque blobs without honoring update and archive behavior.

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

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import type { SignalProtocolRelayServer } from "@open-e2ee/signal-protocol-sdk/remote/relay";
import type { SignalProtocolRemoteObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store";
import type { SignalProtocolLocalStore } from "@open-e2ee/signal-protocol-sdk/local/store";
```

Then compose them through `createSignalProtocolClient()`:

<!-- doc-snippet:skip requires-external-context -->
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

In-memory relay and storage adapters provide deterministic behavior for
development environments. Production adapters remain dependency-injected so
applications can evaluate storage, delivery, and failure behavior without
reaching into client internals.

## Related Docs

- [README](./README.md)
- [Remote Guide](./remote/README.md)
- [Storage Guide](./local/store/README.md)
- [Client Guide](./client/README.md)
