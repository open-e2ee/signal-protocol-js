# Recipes

> Navigation: [README](../README.md) | [Getting Started](./GETTING_STARTED.md) |
> [Package Surface](./PACKAGE_SURFACE.md) |
> [Client Composition](./CLIENT_COMPOSITION.md) |
> [Protocol Policy](./PROTOCOL_POLICY.md)

Working shapes for the operations applications perform most often. Each example
uses public exports only.

## Two local clients

This local demo sends while Bob is offline so you can see the relay's encrypted
envelope and Bob's decrypted plaintext in the same workflow.

<!-- doc-snippet:run recipes-two-local-clients expect="bob decrypted: alice: hello" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";

const relay = inMemoryRelay();

// The relay knows which devices exist, but it does not get plaintext.
await relay.registerDevice("alice", {
  encryptedDeviceName: new ArrayBuffer(0),
});
await relay.registerDevice("bob", { encryptedDeviceName: new ArrayBuffer(0) });

// Each client represents one device. Its storage is local to that device.
const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: inMemoryStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: inMemoryStore(), relay },
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

## Production composition with Convex + Expo

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;

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
    storage: expoStore(),
    relay,
  },
});

// Publish this device's public prekeys so other devices can start sessions.
await signal.syncToServer();
```

Production bootstrapping must register or provision the current device with the
relay before other clients rely on user-level send discovery. In Signal Protocol
that belongs in the device lifecycle and authentication bootstrap. Expo apps
must also complete the [database bootstrap](../local/store/expo/README.md)
before creating the client.

## Local development

<!-- doc-snippet:run recipes-local-development expect="" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";

const relay = inMemoryRelay();

const alice = await createSignalProtocolClient({
  // `identity` is the app account/device being represented.
  identity: { userId: "alice" },
  // `adapters` are the concrete storage/relay implementation for this run.
  adapters: { storage: inMemoryStore(), relay },
});

const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: inMemoryStore(), relay },
});
```

## App message flow

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

## Protocol policy

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
ML-KEM Braid SPQR profile. See the [protocol policy](./PROTOCOL_POLICY.md) for
supported choices.

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

## Multi-device send

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

## Direct device session

```ts
import { ProtocolAddress } from "@open-e2ee/signal-protocol-sdk";

const bob = ProtocolAddress.create("bob", 2);
await signal.establishSession(bob, bundle);
await signal.encryptMessage(bob, "linked-device hello");
```

## Username and ZK helpers

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

## Encrypted attachments

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

See the [encrypted media guide](../media/README.md) and
[remote object storage](../remote/README.md) for the transfer and object-store
contracts these examples compose.
