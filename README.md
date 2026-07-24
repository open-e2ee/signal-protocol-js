# OpenE2EE Signal Protocol SDK

> **Not affiliated with Signal Messenger.** OpenE2EE
> (`@open-e2ee/signal-protocol-sdk`) is an independently maintained TypeScript
> SDK with its own versioned messaging profile, based on the public
> [Signal Protocol specifications](https://signal.org/docs/).
>
> In this repository, **Signal Protocol** means the published protocol
> specification family. **Signal Messenger** means the separate messaging
> product and service. This project is not Signal Messenger and is not
> affiliated with, endorsed by, sponsored by, or maintained by Signal Messenger
> LLC or Signal Technology Foundation. It does not claim general wire
> compatibility with Signal Messenger. See the public
> [security model](./docs/SECURITY.md) and
> [protocol policy](./docs/PROTOCOL_POLICY.md) for supported behavior. See
> [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES](./THIRD_PARTY_NOTICES.md) for
> legal notices.

> Navigation: **README** | [ARCHITECTURE](./ARCHITECTURE.md) | [ADAPTERS](./ADAPTERS.md) | [SECURITY MODEL](./docs/SECURITY.md) | [API Reference](./docs/api/README.md)

`@open-e2ee/signal-protocol-sdk` is a reusable encrypted messaging package for TypeScript apps.
It gives app code a small client API for encrypted messaging, devices,
attachments, groups, safety numbers, and explicit storage/relay composition.

The current release line is `0.1.0-alpha.x`. Public APIs and persisted formats
may change before `1.0`.

OpenE2EE is the project and package namespace; it is not the name of a single
protocol client. The protocol-specific package and client names leave that
namespace clear for other E2EE protocol implementations, such as a future
[Messaging Layer Security (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html)
package, without implying that one client spans multiple protocols.

## Core Model

- `createSignalProtocolClient()` is the recommended app-facing entry point.
- `SignalProtocolClient` is the primary class returned by the factory.
- `storage` is required and owns local encryption state for one user/device.
- `relay` is optional for local development, but real messaging apps use it for key
  sync, message delivery, device fanout, and linked-device workflows.
- Secure post-quantum defaults are enabled without extra configuration.
- Identity trust is pinned to one versioned X25519 + Ed25519 composite tuple
  per `(userId, identityType)`; first contact remains unverified TOFU.
- The root package is intentionally core-only. Platform and backend adapters
  live on explicit subpaths.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

App consumers should also install any runtime dependencies their chosen adapters
need, such as Expo or Convex client packages (declared as optional peer
dependencies).

## Setup Sequence

For a production app, the normal startup shape is:

1. Choose device-local storage for the current user/device.
2. Choose a relay for device discovery, public prekeys, and encrypted delivery.
3. Register or provision the current device with the relay during app bootstrap.
4. Create the Signal Protocol client with `createSignalProtocolClient()`.
5. Call `syncToServer()` so other devices can start encrypted sessions.
6. Register receive hooks and start relay subscription delivery.

## Quick Start

### Two Local Clients

This local demo sends while Bob is offline so you can see the relay's encrypted
envelope and Bob's decrypted plaintext in the same workflow.

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";

const relay = mockRelay();

// The relay knows which devices exist, but it does not get plaintext.
await relay.registerDevice("alice", {
  encryptedDeviceName: new ArrayBuffer(0),
});
await relay.registerDevice("bob", { encryptedDeviceName: new ArrayBuffer(0) });

// Each client represents one device. Its storage is local to that device.
const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: mockStore(), relay },
});

await alice.syncToServer();
await bob.syncToServer();

// Send while Bob is offline so we can inspect what the relay stores.
const sent = await alice.send("bob", "hello");
console.log("alice sent:", sent.messageId);

// The relay-visible envelope contains metadata plus ciphertext, not plaintext.
const [queuedEnvelope] = relay.getPendingMessages("bob", 1);
const ciphertextLength =
  typeof queuedEnvelope.ciphertext === "string"
    ? queuedEnvelope.ciphertext.length
    : queuedEnvelope.ciphertext.byteLength;
const ciphertextPreview =
  typeof queuedEnvelope.ciphertext === "string"
    ? `${queuedEnvelope.ciphertext.slice(0, 32)}...`
    : `${queuedEnvelope.ciphertext.byteLength} encrypted bytes`;

console.log("relay sees encrypted envelope:", {
  messageType: queuedEnvelope.messageType,
  ciphertextLength,
  ciphertextPreview,
});

const decrypted = new Promise<void>((resolve) => {
  // Plaintext enters your app only after Bob's Signal Protocol client decrypts it.
  bob.registerHook("onMessageDecrypted", async (message) => {
    console.log("bob decrypted:", `${message.senderId}: ${message.content}`);
    resolve();
  });
});

// Starting the subscription delivers Bob's queued encrypted envelope.
bob.startRelaySubscription();
await decrypted;
```

Example output:

```text
alice sent: msg-1
relay sees encrypted envelope: {
  messageType: 'prekey_bundle',
  ciphertextLength: 3464,
  ciphertextPreview: '<base64 ciphertext preview>...'
}
bob decrypted: alice: hello
```

The first message usually uses a `prekey_bundle` envelope because it establishes
the session. Later messages on the same session use `ciphertext`. In both cases
the relay sees encrypted envelope bytes; decrypted content is only surfaced to
Bob through the `onMessageDecrypted` hook.

### Production composition with Convex + Expo

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  convexRelay,
  type ConvexSignalRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalRelayApi;

// The relay handles server-side public keys, devices, and encrypted envelopes.
const relay = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});

// Initialize the application-owned Expo/SQLCipher database bindings first.
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    // Storage owns this device's private keys and session state.
    storage: expoStore({ relay }),
    relay,
  },
});

// Publish this device's public prekeys so other devices can start sessions.
await signal.syncToServer();
```

Production bootstrapping must register or provision the current device with the
relay before other clients rely on user-level send discovery. In Signal Protocol
that belongs in the device lifecycle and authentication bootstrap. Expo apps
must also complete the [database bootstrap](./local/store/expo/README.md) before
creating the client.

### Local development

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const relay = mockRelay();

const alice = await createSignalProtocolClient({
  // `identity` is the app account/device being represented.
  identity: { userId: "alice" },
  // `adapters` are the concrete storage/relay implementation for this run.
  adapters: { storage: mockStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: mockStore(), relay },
});
```

## Public Surface

### Root package

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

The root package intentionally does not re-export platform-bound adapters like Expo storage or Convex helpers.

### Integration subpaths

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

### Module guides

- [Client](./client/README.md)
- [Device lifecycle, linking, and transfer](./device/README.md)
- [Keys and identity](./keys/README.md)
- [Local stores](./local/store/README.md)
- [Local secret vault](./local/vault/README.md)
- [Remote relay and object storage](./remote/README.md)
- [Encrypted media](./media/README.md)
- [Encrypted files](./files/README.md)
- [Groups](./groups/README.md)
- [Safety numbers](./safety/README.md)
- [Encrypted profiles](./profile/README.md)
- [Usernames](./username/README.md)
- [Blocking](./blocking/README.md)
- [React hooks](./hooks/README.md)
- [Encoding](./encoding/README.md)
- [Public types](./types/README.md)
- [Zero-knowledge credentials and groups](./zk/README.md)
- [Documentation and comment standards](./docs/DOCUMENTATION_STANDARDS.md)

## Basic Concepts

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

## Supported Implementations

### Relay implementations

- `ConvexSignalRelayServer` for Convex-backed apps
- `convexRelay()` for Convex-backed composition
- `MockSignalRelayServer` / `mockRelay()` for local development
- custom implementations via `ISignalRelayServer`

### Storage implementations

- `ExpoSignalStore` for Expo / React Native
- `expoStore()` for Expo / React Native composition
- `@open-e2ee/signal-protocol-sdk/local/store/expo` also exports the Expo helpers Signal Protocol composes directly:
  `getKeyStorage`, `getDatabaseKeyManager`, `clearDatabaseKeyCache`, and
  `createPreKeyMaintenanceStore`
- `IndexedDbSignalStore` / `indexedDbStore()` for browsers (experimental)
- `ReactNativeSignalStore` / `reactNativeStore()` for bare React Native (experimental; provide your own key-value backend)
- `NodeSignalStore` / `nodeStore()` for Node environments
- `MockSignalStore` / `mockStore()` for local development
- custom implementations via `ISignalLocalStore`

### Remote object storage

- `ConvexR2ObjectStore` via `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `convexR2ObjectStore()` for Cloudflare R2 composition
- `defineConvexR2ObjectStore()` via the server-only
  `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server` entry point
- `S3ObjectStore` via `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- `s3ObjectStore()` for brokered Amazon S3 or S3-compatible storage
- custom implementations via `SignalRemoteObjectStore`

`ConvexR2ObjectStore` is a client adapter for authenticated app-owned Convex
functions that wrap `@convex-dev/r2`; it is not the Convex component itself.
The application continues to own component installation, mounting,
configuration, authentication, authorization, persistence, credentials, and
the R2 bucket. The optional server helper owns only generic broker mechanics.
Both concrete adapters keep provider credentials in the application backend.

Remote object storage is a normal first-class integration point for encrypted
attachments and files, not a niche or internal-only adapter.
Use `attachment.transfer` when your app has a foreground, background,
resumable, or platform-native byte transfer implementation. The Signal package
still owns encryption, digest verification, retry decisions, and pointer
metadata.
Object stores can return signed upload headers, and stores that return
`protocol: 'tus'` automatically use the built-in resumable TUS transfer
helper. You can also pass `media.createTusMediaAttachmentTransfer()` explicitly
when your app wants to tune the TUS fetch implementation or chunk size.
Download credentials can also return signed headers. For JavaScript runtimes
that need resumable downloads, `media.createByteRangeMediaAttachmentTransfer()`
performs strict HTTP range requests, validates `Content-Range`, persists
checkpoints, and resumes only when your app provides a partial-byte store for the
previous ciphertext prefix. Native background download integrations should
implement the same `MediaAttachmentTransfer` seam.

```ts
import { media } from "@open-e2ee/signal-protocol-sdk";

await signal.send(recipientUserId, photoBytes, {
  isBinary: true,
  mimeType: "image/jpeg",
  width: 1200,
  height: 800,
  thumbnail: thumbnailBase64,
  attachment: {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Image,
    onProgress: (event) => {
      console.log(
        event.operation,
        event.phase,
        event.bytesTransferred,
        event.totalBytes,
      );
    },
  },
});

const attachment = await signal.uploadAttachment(photoBytes, {
  mimeType: "image/jpeg",
  fileName: "photo.jpg",
  width: 1200,
  height: 800,
  thumbnail: thumbnailBase64,
  attachment: {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Image,
  },
});

const mediaWork = media.planMediaAttachmentProcessing({
  attachment,
  senderUserId,
  timestamp: messageTimestamp,
  processedDeliveryIds: await appMessages.processedMediaDeliveryIds(),
  cachedAttachmentIds: await appMediaCache.attachmentIds(),
  openedViewOnceDeliveryIds: await appMediaCache.openedViewOnceDeliveryIds(),
});

if (mediaWork.downloadJob) {
  await signal.media.download(
    {
      attachment,
      senderUserId,
      timestamp: messageTimestamp,
      processedDeliveryIds: await appMessages.processedMediaDeliveryIds(),
      cachedAttachmentIds: await appMediaCache.attachmentIds(),
      openedViewOnceDeliveryIds:
        await appMediaCache.openedViewOnceDeliveryIds(),
    },
    {
      transfer: appMediaTransferAdapter,
      onCheckpoint: appMediaTransfers.save,
    },
  );
}

const downloaded = await signal.downloadAttachment(attachment, {
  transfer: media.createByteRangeMediaAttachmentTransfer({
    chunkSizeBytes: 1024 * 1024,
    partialStore: appMediaTransfers.partialStore(),
  }),
  resume: await appMediaTransfers.resumeState(mediaWork.attachmentId),
  onCheckpoint: (checkpoint) => appMediaTransfers.save(checkpoint),
});

const opened = media.planMediaAttachmentOpen({
  attachment,
  senderUserId,
  timestamp: messageTimestamp,
});

if (opened.viewOnceOpenSync) {
  await signal.syncViewOnceOpenToLinkedDevices(opened.viewOnceOpenSync);
}

if (opened.cleanup?.deleteLocalCache) {
  await appMediaCache.delete(opened.cleanup.storageId);
}

const deleteSync = media.planMediaAttachmentDeleteSync({
  attachment,
  reason: media.MediaAttachmentCleanupReason.MessageDeleted,
  deletedAt: Date.now(),
});

await appMediaCache.delete(deleteSync.storageId);
await signal.syncMediaAttachmentDeleteToLinkedDevices(deleteSync);

await signal.media.cleanup(
  {
    cleanup: media.planMediaAttachmentCleanup(
      attachment,
      media.MediaAttachmentCleanupReason.MessageExpired,
    ),
    includeLocal: true,
    includeRemote: true,
    includeSync: true,
  },
  {
    transfer: appMediaTransferAdapter,
  },
);
```

## Common Patterns

### App Message Flow

```ts
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});

// Upload public prekeys before other devices need to message this device.
await signal.syncToServer();

signal.registerHook("onMessageDecrypted", async (message) => {
  // Decrypted content belongs in your app database, not in the relay.
  await appMessages.insert({
    conversationId: message.conversationId,
    senderId: message.senderId,
    body: message.content,
    receivedAt: message.receivedAt,
  });
});

// Subscribing starts encrypted envelope delivery and local decryption.
signal.startRelaySubscription();

await signal.send(recipientUserId, "hello");
```

The relay only handles encrypted envelopes. Your application owns decrypted
message storage through hooks.

### Protocol policy

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: "required",
    braid: "required",
  },
});
```

`postQuantum: 'required'` and `braid: 'required'` are the defaults. Peers
without post-quantum material fail closed, and PQ sessions use the SDK's
ML-KEM Braid SPQR profile. See the
[protocol policy](./docs/PROTOCOL_POLICY.md) for supported choices.

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: "compatible",
    braid: "required",
  },
});
```

`postQuantum: 'compatible'` still uses post-quantum sessions whenever the peer
supports them. It only allows classical compatibility for peers that advertise
no post-quantum material at all.

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: "required",
    braid: "disabled",
  },
});
```

`braid: 'disabled'` is an explicit direct-SPQR escape hatch for
product-reviewed constraints. It is not downgrade recovery and does not relax
PQXDH strictness.

### Multi-device send

```ts
const result = await signal.send(recipientUserId, "hello");
await appMessages.insertOutgoing({
  messageId: result.messageId,
  conversationId,
  body: "hello",
  sentAt: result.clientTimestamp ?? result.timestamp,
  recipientDeviceCount: result.recipientDeviceCount,
});
```

### Direct device session

```ts
import { ProtocolAddress } from "@open-e2ee/signal-protocol-sdk";

const bob = ProtocolAddress.create("bob", 2);
await signal.establishSession(bob, bundle);
await signal.encryptMessage(bob, "linked-device hello");
```

### Username and ZK helpers

```ts
import {
  hashUsername,
  parseUsername,
} from "@open-e2ee/signal-protocol-sdk/username";
import { computeProfileKeyVersion } from "@open-e2ee/signal-protocol-sdk/zk/groups";

const parsed = parseUsername("alice.42");
const usernameHash = hashUsername(parsed.nickname, parsed.discriminator);
const version = computeProfileKeyVersion(profileKeyBytes, userIdBytes);
```

## Design Notes

- `SignalProtocolClient.create()` requires `storage`. There are no hidden default adapters.
- `createSignalProtocolClient()` is the preferred composition helper when app code owns
  multiple adapters.
- Linked devices must already contain provisioned identity material before `SignalProtocolClient.create(..., { deviceId: 2 })`.
- Username-only apps typically run ACI-only. Phone-capable apps can enable both ACI and PNI with `enablePniKeys: true`.
- `protocol.postQuantum` and `protocol.braid` are product-facing policy.
  Advanced protocol strategy knobs remain available for diagnostics, telemetry,
  and protocol-level tuning.
- The package is workspace-friendly in this repo and dist-first for packed consumers.

## Further Reading

- [ARCHITECTURE](./ARCHITECTURE.md)
- [ADAPTERS](./ADAPTERS.md)
- [Getting Started](./docs/GETTING_STARTED.md)
- [Client Composition Guide](./docs/CLIENT_COMPOSITION.md)
- [Protocol Policy Guide](./docs/PROTOCOL_POLICY.md)
- [Security Model](./docs/SECURITY.md)
- [Documentation and Comment Standards](./docs/DOCUMENTATION_STANDARDS.md)
- [Remote Guide](./remote/README.md)
- [Storage Guide](./local/store/README.md)
- [API Reference](./docs/api/README.md)

## License and Warranty

This project is licensed under `AGPL-3.0-or-later`; see [LICENSE](./LICENSE).
The software is provided **as is**, without warranties or conditions of any
kind. To the extent permitted by applicable law, copyright holders and
contributors are not liable for damages arising from its use. Applications are
responsible for evaluating the SDK for their requirements and for securing
their own deployment, storage, authentication, authorization, and operations.

This summary does not modify the license. The complete warranty disclaimer and
limitation of liability are in sections 15 and 16 of the GNU Affero General
Public License.
