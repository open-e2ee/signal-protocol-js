# Getting Started

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) | **Getting Started**

Use the OpenE2EE Signal Protocol SDK with the OpenE2EE Signal Protocol Relay
for authenticated delivery. The SDK owns device-local encryption and protocol
state. The Relay holds public key material, encrypted envelopes, and routing
metadata. The relay never needs message plaintext or device private keys.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

Install the runtime dependencies that your device-local store requires.
The [adapter guide](../ADAPTERS.md) lists the supported stores.

## What You Need

- A Relay project and its environment connection URL. In the application
  directory, `oe new` creates the project and its Sandbox environment, and it
  writes the connection URL to `.env.local` as `OPEN_E2EE_RELAY_URL`. In a
  Next.js, Expo, or Vite application, the name has the public prefix of the
  framework, for example `EXPO_PUBLIC_OPEN_E2EE_RELAY_URL`.
- A `getIdentityAssertion` callback that returns a short-lived signed assertion.
- Device-local storage for private keys, sessions, and delivery state.
- Application storage for decrypted messages and attachment bytes.

A Sandbox environment uses device-owned identity. `hostedRelaySandboxIdentity`
creates its `getIdentityAssertion` callback. The callback signs each assertion
with a key that it keeps in the device-local store, so the device gets the same
account each time it registers. A device that loses its store loses that
Sandbox account. The helper works only in a Sandbox environment.

In production, the callback belongs to your authentication integration. It
returns a short-lived assertion for the signed-in user from your identity
provider. The SDK does not supply an identity provider or a relay server
implementation.

## Setup Sequence

1. Run `oe new` to create the Relay project and its Sandbox environment.
2. Open the device-local store for the device.
3. Create the client with `createHostedSignalProtocolClient()`. In a Sandbox
   environment, pass `hostedRelaySandboxIdentity(storage)` as
   `hosted.getIdentityAssertion`.
4. Register a receive handler that persists decrypted messages.
5. Start the relay subscription.

The hosted factory authenticates and registers the current device, then publishes
its public prekeys. Linked devices use the provisioning flow in the
[device guide](../device/README.md). The default policy requires post-quantum
session establishment and Braid ratcheting.

## Expo Client

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  createHostedSignalProtocolClient,
  hostedRelaySandboxIdentity,
} from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";

const storage = await expoStore();
const signal = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    relayUrl: process.env.EXPO_PUBLIC_OPEN_E2EE_RELAY_URL!,
    // Sandbox only. In production, use your identity provider's callback.
    getIdentityAssertion: hostedRelaySandboxIdentity(storage),
  },
});
```

Complete the [Expo database setup](../local/store/expo/README.md) before creating
the client. Use a Sandbox connection URL during development. Keep each
account's device-local state separate.

## Custom Transport

Advanced integrations can use `createSignalProtocolClient()` with an
application-owned `SignalProtocolRelayServer` client transport. That transport
connects to an authenticated backend. The [interface guide](./INTERFACES.md)
defines the contract. The published SDK contains no relay server implementation.

## Receive Messages

Register a receive hook before starting the relay subscription:

<!-- doc-snippet:skip requires-external-context -->
```ts
signal.registerHook("onMessageDecrypted", async (message) => {
  // Decrypted content belongs in your app database, not in the relay.
  await appMessages.insert({
    messageId: message.messageId,
    conversationId: message.conversationId,
    senderId: message.senderId,
    senderDeviceId: message.senderDeviceId,
    body: message.content,
    receivedAt: message.receivedAt,
  });
});

// Subscribing starts encrypted envelope delivery and local decryption.
signal.startRelaySubscription();
```

The package does not own your product database or UI state. It decrypts messages
and hands the app a `DecryptedEnvelope`.

## Send Messages

Send by recipient user ID for normal one-to-one and multi-device delivery:

<!-- doc-snippet:skip requires-external-context -->
```ts
await signal.send("bob", "hello");
```

For structured app messages, pass an object:

<!-- doc-snippet:skip requires-external-context -->
```ts
await signal.send("bob", {
  body: "hello",
  conversationId: "dm:alice_bob",
  timestamp: Date.now(),
});
```

A hosted client sends a sealed 1:1 message only when you pass
`hosted.profileKeys`, and only to a contact whose profile key `contacts` holds.
Each other 1:1 message is identified, so the Relay sees its sender. Until the
client holds the profile key of a contact, its messages to that contact are
identified and carry the profile key of this account.

## Attachments

Add a remote object store when your app sends encrypted attachments. The
`remoteObjectStore` adapter brokers encrypted byte objects rather than
plaintext files.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient, media } from "@open-e2ee/signal-protocol-sdk";
import { convexR2ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2";
import { api } from "../convex/_generated/api";

const signal = await createHostedSignalProtocolClient({
  hosted: { relayUrl, getIdentityAssertion },
  adapters: {
    storage,
    remoteObjectStore: convexR2ObjectStore({
      convex,
      api: api.signalObjectStore,
    }),
  },
  media: {
    preparedUploads: appPreparedUploads,
    maxPreparedUploadBytes: appUploadBudgetBytes,
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

For Amazon S3 or S3-compatible storage, use the framework-neutral adapter with
an authenticated application-backend broker:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { s3ObjectStore } from "@open-e2ee/signal-protocol-sdk/remote/object-store/s3";

const remoteObjectStore = s3ObjectStore({
  broker: {
    createUpload: (input) => storageApi.createS3Upload(input),
    createDownload: (input) => storageApi.createS3Download(input),
    completeUpload: (input) => storageApi.completeS3Upload(input),
    deleteObject: (input) => storageApi.deleteS3Object(input),
  },
});
```

Keep AWS credentials and AWS SDK clients on that backend. The app should
receive only narrowly scoped, short-lived upload, download, and delete
operations.

Send bytes when the attachment travels as its own encrypted message:

<!-- doc-snippet:skip requires-external-context -->
```ts
const controller = new AbortController();

await signal.send("bob", photoBytes, {
  isBinary: true,
  mimeType: "image/jpeg",
  fileName: "photo.jpg",
  width: 1200,
  height: 800,
  thumbnail: thumbnailBase64,
  attachment: {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    signal: controller.signal,
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
```

Upload first when your app message format embeds the attachment pointer inside a
larger payload:

<!-- doc-snippet:skip requires-external-context -->
```ts
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

await signal.send("bob", {
  body: "trip photo",
  attachments: [attachment],
  timestamp: Date.now(),
});
```

Progress callbacks include `retry` events with `reason`, `status`, and
`retryInMs` so product code can distinguish an expired upload/download URL from
a generic transient failure.

`attachment.transfer` is where production apps plug in their foreground or
background transfer adapter. The Signal Protocol client still owns encryption, digest
verification, retries, and pointer metadata. The adapter owns how bytes move
over the network.

If your object store returns TUS credentials, including `protocol: 'tus'`, the
client uses the built-in TUS transfer helper
automatically. Passing `media.createTusMediaAttachmentTransfer()` explicitly is
useful when the app needs custom chunk sizing or a platform-specific `fetch`.

For downloads in JavaScript runtimes, `media.createByteRangeMediaAttachmentTransfer()`
provides a reviewed HTTP `Range` adapter. It validates `Content-Range`, forwards
signed download headers from the object store, and emits checkpoints. It resumes
from a non-zero offset only when your app provides the partial ciphertext prefix
through a partial-byte store. Native background download code should implement the same
`MediaAttachmentTransfer` interface.

For background-safe uploads, use the durable client operation. The current API
persists bounded recovery metadata through the existing Signal Protocol storage
adapter. The operation tries the upload when it is due and
returns either a completed pointer or a pending job id for later recovery:

<!-- doc-snippet:skip requires-external-context -->
```ts
const upload = await signal.media.upload(
  {
    localMediaId: draftMedia.id,
    contentType: draftMedia.contentType,
    size: draftMedia.byteLength,
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Video,
  },
  {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    onCheckpoint: appMediaTransfers.save,
  },
);

if (upload.status === "completed") {
  await appComposer.attach(upload.attachment);
}
```

Run pending durable media work on app startup, foreground resume, or from a
background task:

<!-- doc-snippet:skip requires-external-context -->
```ts
await signal.media.processPending({
  limit: 10,
  transfer: appMediaTransferAdapter,
  onCheckpoint: appMediaTransfers.save,
});
```

On receive, ask the media planner what work this device should do. Your app
supplies the IDs it has already processed or cached. The Signal Protocol package
returns the safe next step, and it does not take ownership of your app database:

<!-- doc-snippet:skip requires-external-context -->
```ts
const mediaWork = media.planMediaAttachmentProcessing({
  attachment,
  senderUserId,
  timestamp: messageTimestamp,
  processedDeliveryIds: await appMessages.processedMediaDeliveryIds(),
  cachedAttachmentIds: await appMediaCache.attachmentIds(),
  openedViewOnceDeliveryIds: await appMediaCache.openedViewOnceDeliveryIds(),
});

if (mediaWork.shouldPersistMessage) {
  await appMessages.insert(message);
}

if (mediaWork.cleanup?.deleteLocalCache) {
  await appMediaCache.delete(mediaWork.cleanup.storageId);
}

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
      transfer: media.createByteRangeMediaAttachmentTransfer({
        chunkSizeBytes: 1024 * 1024,
        partialStore: appMediaTransfers.partialStore(),
      }),
    },
  );
}
```

If the planner says this device needs media bytes, pass the decrypted attachment
pointer back to the client. The client downloads encrypted blob bytes, verifies
the digest, authenticates the stream, and returns plaintext bytes:

<!-- doc-snippet:skip requires-external-context -->
```ts
if (mediaWork.shouldDownload) {
  const downloaded = await signal.downloadAttachment(attachment, {
    transfer: media.createByteRangeMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
      partialStore: appMediaTransfers.partialStore(),
    }),
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Image,
    resume: await appMediaTransfers.resumeState(mediaWork.attachmentId),
    onCheckpoint: (checkpoint) => appMediaTransfers.save(checkpoint),
    onProgress: (event) => {
      console.log(
        event.operation,
        event.phase,
        event.bytesTransferred,
        event.totalBytes,
      );
    },
  });

  await appMediaCache.put(mediaWork.attachmentId, downloaded.data);

  console.log(downloaded.contentType);
  console.log(downloaded.data.byteLength);
  console.log(downloaded.width, downloaded.height, downloaded.thumbnail);
}
```

If the attachment is view-once, plan the local cleanup and linked-device sync
after the user opens it:

<!-- doc-snippet:skip requires-external-context -->
```ts
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

if (opened.cleanup?.deleteRemoteBlob) {
  await signal.deleteRemoteAttachment(attachment);
}
```

A message delete or expiration can remove media on this account's linked
devices. Plan and sync the deletion after your app applies the local cleanup:

<!-- doc-snippet:skip requires-external-context -->
```ts
const deleteSync = media.planMediaAttachmentDeleteSync({
  attachment,
  reason: media.MediaAttachmentCleanupReason.MessageDeleted,
  deletedAt: Date.now(),
});

await appMediaCache.delete(deleteSync.storageId);
await signal.syncMediaAttachmentDeleteToLinkedDevices(deleteSync);
```

When a worker must do the cleanup, use the durable client operation:

<!-- doc-snippet:skip requires-external-context -->
```ts
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

## Security Policy

The default is:

<!-- doc-snippet:illustrative config-object-fragment -->
```ts
protocol: {
  postQuantum: 'required',
  braid: 'required',
}
```

Leave it unset unless your product has a specific compatibility decision. See
[Protocol Policy](./PROTOCOL_POLICY.md) for the rare cases where you would set
`postQuantum: 'compatible'` or `braid: 'disabled'`.

## Where To Go Next

- [Client Composition](./CLIENT_COMPOSITION.md): app setup and adapter shape.
- [Protocol Policy](./PROTOCOL_POLICY.md): security policy choices.
- [Adapters](../ADAPTERS.md): device-local storage, client transports, and remote
  object stores.
- [API Reference](./api/README.md): generated TypeScript API docs.
