# Recipes

> Navigation: [README](../README.md) | [Getting Started](./GETTING_STARTED.md) |
> [Package Surface](./PACKAGE_SURFACE.md) |
> [Client Composition](./CLIENT_COMPOSITION.md) |
> [Protocol Policy](./PROTOCOL_POLICY.md)

Working shapes for the tasks applications do most often. Each example
uses public exports only.

## Hosted Client Setup

The recipes require a configured Relay project, an identity-assertion callback,
and device-local storage. Use a Sandbox environment for development, where
`hostedRelaySandboxIdentity(storage)` supplies the callback. The
[getting-started guide](./GETTING_STARTED.md) describes these inputs.

## Production composition with Expo on the Signal Protocol Relay

<!-- doc-snippet:skip requires-external-context -->
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

The hosted factory authenticates and registers the current device. Expo apps
must complete the [database setup](../local/store/expo/README.md) first.

## App message flow

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
```ts
import { ProtocolAddress } from "@open-e2ee/signal-protocol-sdk";

const bob = ProtocolAddress.create("bob", 2);
await signal.establishSession(bob, bundle);
await signal.encryptMessage(bob, "linked-device hello");
```

## Username and ZK helpers

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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
[remote object store](../remote/README.md) for the transfer and object-store
contracts these examples compose.
