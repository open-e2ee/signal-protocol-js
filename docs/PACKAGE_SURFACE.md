# Package Surface

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) |
> [ADAPTERS](../ADAPTERS.md) | [Recipes](./RECIPES.md) |
> [Security Model](./SECURITY.md) | [API Reference](./api/README.md)

This document is the complete public surface of
`@open-e2ee/signal-protocol-sdk`: what the root package exports, every
supported subpath, the adapter implementations that ship with the package, and
the vocabulary the rest of the documentation assumes.

## Core model

- `createSignalProtocolClient()` is the recommended app-facing entry point.
- `SignalProtocolClient` is the primary class returned by the factory.
- `storage` is required and owns local encryption state for one user/device.
- `relay` is optional for local development, but real messaging apps use it for
  key sync, message delivery, device fanout, and linked-device workflows.
- Secure post-quantum defaults are enabled without extra configuration.
- Identity trust is pinned to one versioned X25519 + Ed25519 composite tuple
  per `(userId, identityType)`; first contact remains unverified TOFU.
- The root package is intentionally core-only. Platform and backend adapters
  live on explicit subpaths.

OpenE2EE is the project and package namespace; it is not the name of a single
protocol client. The protocol-specific package and client names leave that
namespace clear for other E2EE protocol implementations, such as a future
[Messaging Layer Security (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html)
package, without implying that one client spans multiple protocols.

## Setup sequence

For a production app, the normal startup shape is:

1. Choose device-local storage for the current user/device.
2. Choose a relay for device discovery, public prekeys, and encrypted delivery.
3. Register or provision the current device with the relay during app bootstrap.
4. Create the Signal Protocol client with `createSignalProtocolClient()`.
5. Call `syncToServer()` so other devices can start encrypted sessions.
6. Register receive hooks and start relay subscription delivery.

## Root package

Use the root package for core portable APIs:

```ts
import {
  SignalProtocolClient,
  createSignalProtocolClient,
  ProtocolAddress,
  BraidPolicy,
  PostQuantumPolicy,
  keys,
  safety,
  encoding,
} from "@open-e2ee/signal-protocol-sdk";
```

The root package intentionally does not re-export platform-bound adapters like
Expo storage or Convex helpers.

## Integration subpaths

- `@open-e2ee/signal-protocol-sdk/remote/relay`
- `@open-e2ee/signal-protocol-sdk/remote/relay/convex`
- `@open-e2ee/signal-protocol-sdk/remote/relay/convex/relay`
- `@open-e2ee/signal-protocol-sdk/remote/relay/mock`
- `@open-e2ee/signal-protocol-sdk/remote/relay/types`
- `@open-e2ee/signal-protocol-sdk/remote/object-store`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- `@open-e2ee/signal-protocol-sdk/client`
- `@open-e2ee/signal-protocol-sdk/client/config`
- `@open-e2ee/signal-protocol-sdk/client/compose`
- `@open-e2ee/signal-protocol-sdk/client/constants`
- `@open-e2ee/signal-protocol-sdk/client/endorsement-manager`
- `@open-e2ee/signal-protocol-sdk/client/headless`
- `@open-e2ee/signal-protocol-sdk/client/types`
- `@open-e2ee/signal-protocol-sdk/device`
- `@open-e2ee/signal-protocol-sdk/device/constants`
- `@open-e2ee/signal-protocol-sdk/device/device-id`
- `@open-e2ee/signal-protocol-sdk/device/lifecycle`
- `@open-e2ee/signal-protocol-sdk/device/provisioning`
- `@open-e2ee/signal-protocol-sdk/encoding`
- `@open-e2ee/signal-protocol-sdk/encoding/hex`
- `@open-e2ee/signal-protocol-sdk/files`
- `@open-e2ee/signal-protocol-sdk/groups`
- `@open-e2ee/signal-protocol-sdk/hooks`
- `@open-e2ee/signal-protocol-sdk/hooks/use-connection-presence`
- `@open-e2ee/signal-protocol-sdk/keys`
- `@open-e2ee/signal-protocol-sdk/keys/generation`
- `@open-e2ee/signal-protocol-sdk/keys/types`
- `@open-e2ee/signal-protocol-sdk/logger`
- `@open-e2ee/signal-protocol-sdk/media`
- `@open-e2ee/signal-protocol-sdk/blocking`
- `@open-e2ee/signal-protocol-sdk/profile`
- `@open-e2ee/signal-protocol-sdk/safety`
- `@open-e2ee/signal-protocol-sdk/sealed-sender`
- `@open-e2ee/signal-protocol-sdk/server-clock`
- `@open-e2ee/signal-protocol-sdk/local/store`
- `@open-e2ee/signal-protocol-sdk/local/store/expo`
- `@open-e2ee/signal-protocol-sdk/local/store/expo/db`
- `@open-e2ee/signal-protocol-sdk/local/store/expo/schema`
- `@open-e2ee/signal-protocol-sdk/local/store/mock`
- `@open-e2ee/signal-protocol-sdk/local/store/node`
- `@open-e2ee/signal-protocol-sdk/local/store/react-native`
- `@open-e2ee/signal-protocol-sdk/local/store/web`
- `@open-e2ee/signal-protocol-sdk/local/vault`
- `@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store`
- `@open-e2ee/signal-protocol-sdk/types`
- `@open-e2ee/signal-protocol-sdk/types/address`
- `@open-e2ee/signal-protocol-sdk/types/messages`
- `@open-e2ee/signal-protocol-sdk/types/utils`
- `@open-e2ee/signal-protocol-sdk/username`
- `@open-e2ee/signal-protocol-sdk/username/link`
- `@open-e2ee/signal-protocol-sdk/utils/retry`
- `@open-e2ee/signal-protocol-sdk/zk/groups`
- `@open-e2ee/signal-protocol-sdk/zk/credentials`

### Development adapters

- `@open-e2ee/signal-protocol-sdk/remote/relay/mock`
- `@open-e2ee/signal-protocol-sdk/local/store/mock`

`internal/**` is implementation-only and not part of the supported external API.

## Basic concepts

- **Client**: one running app instance for one account and one device.
- **User ID**: your app's stable account identifier.
- **Device ID**: `1` for the primary device; linked devices use `2-5`.
- **Storage**: local encrypted state needed to keep conversations working across
  restarts.
- **Relay**: server-side public keys, device lists, encrypted envelope delivery,
  and linked-device coordination.
- **Object store**: optional remote storage for encrypted attachments.
- **Hooks**: callbacks where your app receives decrypted messages and stores them
  in its own database or UI state.

## Supported implementations

### Relay implementations

- `ConvexSignalProtocolRelayServer` for Convex-backed apps
- `convexRelay()` for Convex-backed composition
- `MockSignalProtocolRelayServer` / `mockRelay()` for local development
- custom implementations via `ISignalProtocolRelayServer`

### Storage implementations

- `ExpoSignalProtocolStore` for Expo / React Native
- `expoStore()` for Expo / React Native composition
- `@open-e2ee/signal-protocol-sdk/local/store/expo` also exports the Expo helpers
  Signal Protocol composes directly: `getKeyStorage`, `getDatabaseKeyManager`,
  `clearDatabaseKeyCache`, and `createPreKeyMaintenanceStore`
- `IndexedDbSignalProtocolStore` / `indexedDbStore()` for browsers (experimental)
- `ReactNativeSignalProtocolStore` / `reactNativeStore()` for bare React Native
  (experimental; provide your own key-value backend)
- `NodeSignalProtocolStore` / `nodeStore()` for Node environments
- `MockSignalProtocolStore` / `mockStore()` for local development
- custom implementations via `ISignalProtocolLocalStore`

### Remote object storage

- `ConvexR2ObjectStore` via
  `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `convexR2ObjectStore()` for Cloudflare R2 composition
- `defineConvexR2ObjectStore()` via the server-only
  `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server` entry
  point
- `S3ObjectStore` via `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- `s3ObjectStore()` for brokered Amazon S3 or S3-compatible storage
- custom implementations via `SignalProtocolRemoteObjectStore`

`ConvexR2ObjectStore` is a client adapter for authenticated app-owned Convex
functions that wrap `@convex-dev/r2`; it is not the Convex component itself.
The application continues to own component installation, mounting,
configuration, authentication, authorization, persistence, credentials, and
the R2 bucket. The optional server helper owns only generic broker mechanics.
Both concrete adapters keep provider credentials in the application backend.

Remote object storage is a normal first-class integration point for encrypted
attachments and files, not a niche or internal-only adapter. Use
`attachment.transfer` when your app has a foreground, background, resumable, or
platform-native byte transfer implementation. The Signal Protocol package still
owns encryption, digest verification, retry decisions, and pointer metadata.

Object stores can return signed upload headers, and stores that return
`protocol: 'tus'` automatically use the built-in resumable TUS transfer helper.
You can also pass `media.createTusMediaAttachmentTransfer()` explicitly when
your app wants to tune the TUS fetch implementation or chunk size. Download
credentials can also return signed headers. For JavaScript runtimes that need
resumable downloads, `media.createByteRangeMediaAttachmentTransfer()` performs
strict HTTP range requests, validates `Content-Range`, persists checkpoints, and
resumes only when your app provides a partial-byte store for the previous
ciphertext prefix. Native background download integrations should implement the
same `MediaAttachmentTransfer` seam.

## Design notes

- `SignalProtocolClient.create()` requires `storage`. There are no hidden
  default adapters.
- `createSignalProtocolClient()` is the preferred composition helper when app
  code owns multiple adapters.
- Linked devices must already contain provisioned identity material before
  `SignalProtocolClient.create(..., { deviceId: 2 })`.
- Username-only apps typically run ACI-only. Phone-capable apps can enable both
  ACI and PNI with `enablePniKeys: true`.
- `protocol.postQuantum` and `protocol.braid` are product-facing policy.
  Advanced protocol strategy knobs remain available for diagnostics, telemetry,
  and protocol-level tuning.
- The package is workspace-friendly in this repo and dist-first for packed
  consumers.

## Module guides

- [Client](../client/README.md)
- [Device lifecycle, linking, and transfer](../device/README.md)
- [Keys and identity](../keys/README.md)
- [Local stores](../local/store/README.md)
- [Local secret vault](../local/vault/README.md)
- [Remote relay and object storage](../remote/README.md)
- [Encrypted media](../media/README.md)
- [Encrypted files](../files/README.md)
- [Groups](../groups/README.md)
- [Safety numbers](../safety/README.md)
- [Encrypted profiles](../profile/README.md)
- [Usernames](../username/README.md)
- [Blocking](../blocking/README.md)
- [React hooks](../hooks/README.md)
- [Encoding](../encoding/README.md)
- [Public types](../types/README.md)
- [Zero-knowledge credentials and groups](../zk/README.md)
- [Documentation and comment standards](./DOCUMENTATION_STANDARDS.md)
