# Client Composition Guide

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) | [Getting Started](./GETTING_STARTED.md) | **Client Composition**

Use `createSignalProtocolClient()` when app setup owns identity, local device storage,
relay transport, remote encrypted object storage, logging, and protocol policy
in one place.

This guide documents the current stable composition API. Local persistence is
grouped under device storage, while remote encrypted bytes are supplied by an
explicit object-store adapter. The current API passes protocol storage as
`adapters.storage` and remote attachment storage as `adapters.remoteObjectStore`.

## Target Composition

The target public shape should make platform setup a factory problem, not a
store-by-store wiring exercise:

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { createExpoDeviceStorage } from "@open-e2ee/signal-protocol-sdk/device/storage/expo";
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { convexRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { api } from "../convex/_generated/api";

const signal = await createSignalProtocolClient({
  identity: { userId, deviceId },
  adapters: {
    deviceStorage: createExpoDeviceStorage({ database, files }),
    relay: convexRelay({ convex, api, currentUserId: userId }),
    remoteObjectStore: convexR2ObjectStore({
      convex,
      api: api.signalObjectStore,
    }),
  },
  protocol: {
    postQuantum: "required",
    braid: "required",
  },
});
```

Explicit facets preserve modularity for custom runtimes and independently
verifiable integrations:

```ts
const signal = await createSignalProtocolClient({
  identity: { userId, deviceId },
  adapters: {
    deviceStorage: {
      protocol: protocolStore,
      messages: messageStore,
      files: fileStore,
    },
    relay,
    remoteObjectStore,
  },
});
```

The target receive path should also be message-first:

```ts
const unsubscribe = signal.messages.subscribe(
  { conversationId },
  async (message) => {
    await appMessages.render(message);
  },
);
```

Low-level hooks may remain available for advanced integrations, but ordinary
app code should not depend on hook registration order or manual relay
subscription startup.

## Local Client

<!-- mock-snippet:run client-composition-local-client -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const signal = await createSignalProtocolClient({
  // One Signal Protocol client represents one app account/device.
  identity: { userId: "alice" },
  // Local-only clients can omit a relay, but still need device-local storage.
  adapters: { storage: mockStore() },
});
```

## Expo + Convex Client

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import {
  convexRelay,
  type ConvexSignalRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalRelayApi;

// Convex owns relay-side device lists, public prekeys, and encrypted envelopes.
const relay = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});

const signal = await createSignalProtocolClient({
  identity: { userId, deviceId: 1 },
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: expoStore({ relay }),
    relay,
  },
  logger,
});
```

## Attachments

```ts
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { api } from "../convex/_generated/api";

const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    storage,
    relay,
    // Brokered remote storage of encrypted byte objects.
    remoteObjectStore: convexR2ObjectStore({
      convex,
      api: api.signalObjectStore,
    }),
  },
  media: {
    // The existing Signal Protocol storage adapter persists queue metadata.
    // These callbacks keep app-owned files, plaintext cache, and UI state
    // outside the protocol package.
    loadLocalAttachment: async ({ localMediaId }) =>
      appDraftMedia.readBytes(localMediaId),
    saveUploadedAttachment: async ({ localMediaId, attachment }) =>
      appMediaPointers.save(localMediaId, attachment),
    saveDownloadedAttachment: async ({ attachmentId, downloaded }) =>
      appMediaCache.save(attachmentId, downloaded.data),
    deleteLocalAttachment: async ({ attachmentId }) =>
      appMediaCache.delete(attachmentId),
  },
});
```

The current durable media queue does not require a second queue adapter. It
stores bounded job metadata in `adapters.storage` under SDK-owned namespaced
keys. The target message-first API will move this state behind
`deviceStorage.messages` and local bytes behind `deviceStorage.files`, so app
code does not have to compose queue callbacks for ordinary sends. Do not add a
parallel public `signal.media.*` API once message attachment helpers exist.

## Direct Client Creation

`SignalProtocolClient.create()` remains the low-level primitive. It uses the same
developer-facing protocol config:

```ts
import { SignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";

const signal = await SignalProtocolClient.create(userId, {
  // Low-level creation uses the same storage/relay/protocol concepts.
  storage,
  relay,
  protocol: { postQuantum: "required", braid: "required" },
});
```

## Composition Rules

- Keep platform choices in `adapters`.
- Keep account/device identity in `identity`.
- Keep product security policy in `protocol`.
- Treat `adapters.storage` and `adapters.remoteObjectStore` as current API names; the
  target public DX is `deviceStorage` plus `remoteObjectStore`.
- Keep app logging, hooks, sealed sender, groups, and sender-key options at the
  top level so they match `SignalProtocolClient.create()`.
- Use `protocol.postQuantum: 'compatible'` only when the product explicitly
  supports peers with no post-quantum material.
- Use `protocol.braid: 'disabled'` only when a product-reviewed constraint
  explicitly selects direct SPQR.
