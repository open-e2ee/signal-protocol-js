# Client Composition Guide

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) | [Getting Started](./GETTING_STARTED.md) | **Client Composition**

Use `createSignalProtocolClient()` when app setup owns identity, local device storage,
relay transport, remote encrypted object storage, logging, and protocol policy
in one place.

This guide documents the current stable composition API. It groups local
persistence under device storage, and an explicit object-store adapter supplies
remote encrypted bytes. The current API passes protocol storage as
`adapters.storage` and remote attachment storage as `adapters.remoteObjectStore`.

## Local Client

<!-- doc-snippet:run client-composition-local-client expect="" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const signal = await createSignalProtocolClient({
  // One Signal Protocol client represents one app account/device.
  identity: { userId: "alice" },
  // Local-only clients can omit a relay, but still need device-local storage.
  adapters: { storage: inMemoryStore() },
});
```

## Expo + Convex Client

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;

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
    storage: expoStore(),
    relay,
  },
  logger,
});
```

## Attachments

<!-- doc-snippet:skip requires-external-context -->
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
keys. The intended future shape moves this behind grouped device storage, so
app code does not have to compose queue callbacks for ordinary sends. See
[Future direction](#future-direction-not-shipped). Do not add a parallel public
`signal.media.*` API once message attachment helpers exist.

## Direct Client Creation

`SignalProtocolClient.create()` remains the low-level primitive. It uses the same
developer-facing protocol config:

<!-- doc-snippet:skip requires-external-context -->
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
- Keep app logging, hooks, sealed sender, groups, and sender-key options at the
  top level so they match `SignalProtocolClient.create()`.
- Use `protocol.postQuantum: 'compatible'` only when the product explicitly
  supports peers with no post-quantum material.
- Use `protocol.braid: 'disabled'` only when a product-reviewed constraint
  explicitly selects direct SPQR.

## Future Direction (Not Shipped)

> **Nothing in this section exists in the package.** `deviceStorage`,
> `createExpoDeviceStorage`, and `signal.messages.subscribe` are design intent
> for a future release, recorded here so the direction is public. Importing
> them fails today. The shipped API is everything above this heading.

The intended future shape makes platform setup a factory problem rather than a
store-by-store wiring exercise:

- a grouped `deviceStorage` adapter with `protocol`, `messages`, and `files`
  facets in place of today's flat `adapters.storage`
- a per-platform factory such as a future
  `createExpoDeviceStorage({ database, files })`
- a message-first receive path shaped like
  `signal.messages.subscribe({ conversationId }, handler)` in place of hook
  registration plus manual `startRelaySubscription()`

Low-level hooks would remain for advanced integrations. When this lands it will
be a breaking change and this guide will lead with it. Until then, wire the
current API.
