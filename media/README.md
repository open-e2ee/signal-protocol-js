# Encrypted Media

The media module coordinates encrypted attachment upload, message pointers,
download verification, resumable transfer checkpoints, background jobs, and
cleanup.

## Why it exists

Signal Protocol messages suit small encrypted payloads, not large binary
objects. Media therefore uses two encryption layers:

1. the SDK encrypts file bytes locally, and only ciphertext enters the remote
   object store.
2. the end-to-end encrypted message carries the key, digest, sizes, and opaque
   object identifier.

The remote object store never receives the media key or plaintext.

## Durable upload preparation

`prepareMediaAttachmentUpload()` covers retries within one invocation.
A later invocation must not encrypt different bytes under the same `requestId`.
For restart recovery, use `signal.media.upload()` with `media.preparedUploads` configured.

The application implements `MediaAttachmentPreparedUploadStore` beside its local file storage.
Its atomic `createIfAbsent` operation persists ciphertext and private pointer material together.
Concurrent callers receive the same durable record.
The store returns independent copies and retains records until the queue requests deletion.
It must not evict preparations as disposable cache entries.

`withExclusiveAccess` coordinates queue checks and artifact mutations across clients, tabs, and processes that share the store.
Its callback can use the same store's methods. Process exit must release ownership without a timed lock takeover.
The SDK holds this access only for local queue and artifact work, not provider calls or application callbacks.
The application must not mutate queue-owned artifacts outside this coordination boundary.

Set `media.maxPreparedUploadBytes` from the application's device-local storage budget. The value must be a positive safe integer.
There is no SDK default. The queue reserves each upload's exact ciphertext size before loading or encrypting its draft.
This reservation includes the encoder's header and authentication tags. Pending drafts also hold reservations.

Conditional queue writes enforce the total against shared backing state across clients, tabs, and processes.

The reservation remains until successful cleanup removes the queued upload.
Uncertain authorization, pointer callbacks, or artifact deletion do not release capacity.
If the application lowers its limit, existing uploads can still retry or finish cleanup.
The queue refuses new work that increases an excessive total. It never evicts an upload to make space.

This limit covers ciphertext bytes, not physical disk capacity or encryption memory.
The application must reserve additional space for private metadata, atomic file commits, and its storage adapter.
The existing `maxJobs` setting bounds queue entries separately.
Use one artifact namespace per device-local queue. Independent queues require separate budgets or an application-owned shared storage limit.

The queue persists a small preparation fingerprint before remote authorization.
It saves the canonical object identifier before transfer.
After a successful transfer response, it persists that progress before broker completion.
A lost completion response then retries only completion for the same object.

After a lost transfer response, `reconcileUpload` can verify the original stored object.
The SDK checks its object ID, exact length, and SHA-256 against the saved preparation.
The queue can repeat this check after a client restart without another authorization or transfer.

Unknown outcomes and mismatches remain failures. A conditional refusal alone never proves success.
Metadata-only brokers must omit this capability. The ordinary completion hook does not supply this proof.

It persists the completed pointer before the application's `saveUploadedAttachment` callback.
That callback must be idempotent for the job ID because its result can be lost.
Local cleanup runs only after the queue records callback completion.

After automatic retries stop, a prepared upload keeps its original identity.
The queue also retains intent after a lost preparation-store reply, before its fingerprint exists.
Call `signal.media.upload()` with the same input to retry that job explicitly.
Missing or changed preparation fails without another authorization or new encryption.
Do not reset the queue to recover uncertain remote work.

Broker refusals stop automatic retries without deleting the prepared upload.
The upload result exposes safe guidance in `failure`.
`processPending()` reports retained refusals in `uploadFailures`, including after a restart.
Only an explicit upload call retries a refused preparation.

| Failure code | Required action |
| --- | --- |
| `upload-expired` | Reconcile the existing upload before explicitly starting another upload. |
| `upload-clock-skew` | Correct the device clock. Retry when the saved preparation time is valid, without changing its time or identity. |
| `upload-admission-closed` | Reconcile existing work without moving its admission to another accounting period. |
| `upload-unavailable` | Check deletion or expiry before explicitly starting another upload. |
| `upload-identity-conflict` | Restore the original preparation before retrying. |
| `upload-rejected` | Check connection and permissions without replacing the preparation. |

An expired transfer URL remains retryable with the same prepared bytes.
An uncertain settlement remains retryable even when period-close repair delays it.
A stale connection does not prove that the prepared upload expired.
The queue stores only the refusal code, not provider error text.

Call `signal.media.abandonUpload(jobId)` to abandon a retained upload explicitly.
The broker's `abandonUpload` operation uses the original request ID and preparation time without creating another upload.
Accepted upload usage remains charged. The server retains its refusal and cleanup obligations.
The SDK records abandonment before the call and removes local artifacts only after confirmation.
`processPending()` retries uncertain cancellation and local cleanup with the configured delay. Its `abandoned` count reports completed cleanup.

A `completed` result returns an existing pointer instead of deleting it.
The application's pointer callback can save the pointer before its reply is lost.
Use the existing attachment cleanup operation when the application wants to delete that completed object.
An unsupported broker leaves the queue retained with actionable guidance.

Keep prepared records private on the device, outside queue JSON, logs, and provider payloads.
The supplied store must survive the failures that the application's recovery contract covers.
An in-memory test store does not prove disk or device durability.

Applications with their own scheduler can persist the result of `prepareMediaAttachmentUploadData()`.
They then pass that exact preparation to `uploadPreparedMediaAttachment()`.
The scheduler owns equivalent persistence, callback, and cleanup ordering.
Broker completion recovery and logical upload expiry remain separate server contracts.

## Upload and send

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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
