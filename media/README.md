# Encrypted Media

The media module coordinates encrypted attachment upload, message pointers,
download verification, resumable transfer checkpoints, background jobs, and
cleanup.

## Why it exists

Signal Protocol messages are suited to small encrypted payloads, not large
binary objects. Media therefore uses two encryption layers:

1. file bytes are encrypted locally and only ciphertext enters remote storage;
2. the key, digest, sizes, and opaque object identifier are carried inside the
   end-to-end encrypted message.

The remote object store never receives the media key or plaintext.

## Upload and send

```ts
import {
  createMediaAttachmentMessage,
  prepareMediaAttachmentUpload,
} from "@open-e2ee/signal-protocol-sdk/media";

const attachment = await prepareMediaAttachmentUpload(photoBytes, {
  contentType: "image/jpeg",
  remoteObjectStore,
  transfer: appMediaTransfer,
});

await signal.send(
  recipientUserId,
  JSON.stringify(
    createMediaAttachmentMessage({
      attachment,
      timestamp: Date.now(),
    }),
  ),
);
```

## Receive and open

```ts
import {
  parseMediaAttachmentMessage,
  resolveMediaAttachment,
} from "@open-e2ee/signal-protocol-sdk/media";

const message = parseMediaAttachmentMessage(decryptedContent);

if (message) {
  const resolved = await resolveMediaAttachment(message.attachment, {
    remoteObjectStore,
    transfer: appMediaTransfer,
  });

  await appMediaCache.write(resolved.data);
}
```

`requestId` is a retry-stable idempotency key for one logical upload.
`storageId` is the backend-issued opaque object identifier. The application
must persist checkpoints consistently and must never treat either value as a
provider key.

Validate content policy before rendering decrypted bytes. The application owns
cache retention, view-once enforcement, file-system cleanup, and background
execution policy.

See the [object-store guide](../remote/object-store/README.md) and
[API reference](../docs/api/namespaces/media/README.md).
