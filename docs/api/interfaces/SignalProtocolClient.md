[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClient

# Interface: SignalProtocolClient

High-level encrypted messaging client interface.

All methods accept a ProtocolAddress (userId + deviceId) instead of
string sessionId. This provides type safety and prevents format errors.

## Example

```typescript
import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';

const bob = ProtocolAddress.create('bob', 1);
const encrypted = await signal.encryptMessage(bob, 'Hello!');
```

## Properties

### contentRecoveryStatus

> `readonly` **contentRecoveryStatus**: [`ContentRecoveryStatus`](ContentRecoveryStatus.md)

Whether this client keeps resendable content to answer retry requests.

The client decides at creation, from the `protection` that the local
store declares and from `protocol.contentRecovery`. When `enabled` is
false, `reason` says why, and the client deletes any resendable content
that the store already holds.

***

### deviceId

> `readonly` **deviceId**: `number`

Device ID for this client instance (1 = primary, 2-5 = linked)

***

### logger

> `readonly` **logger**: `Required`\<[`Logger`](Logger.md)\>

Resolved logger for this client instance.

This is the client-scoped logger used throughout the Signal Protocol runtime.

***

### relayConnectionState

> `readonly` **relayConnectionState**: [`RelayConnectionState`](RelayConnectionState.md)

The connection state of the relay subscription.

It reads `stopped` before `startRelaySubscription()`, after
`stopRelaySubscription()`, and when no relay is configured. Use it for a
local indicator of this device's connection.

***

### userId

> `readonly` **userId**: `string`

User ID for this client instance

## Methods

### completeReceive()

> **completeReceive**(`messageId`): `Promise`\<`void`\>

Complete a helper receive: delete its receive record and mark its
envelope processed. Call it after the application stored the content
of a `processed` outcome. An unknown or completed message ID is a no-op.

#### Parameters

##### messageId

`string`

The `messageId` of the `processed` outcome

#### Returns

`Promise`\<`void`\>

***

### createGroupSenderKey()

> **createGroupSenderKey**(`groupId`): `Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Create a new sender key for group messaging

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Sender key ID and distribution message to share with group members

***

### decryptEnvelope()

> **decryptEnvelope**(`envelope`): `Promise`\<\{ `groupContext?`: [`GroupContentContext`](GroupContentContext.md); `plaintext`: `string`; \}\>

Decrypt one envelope with no receive record.

The decrypt installs a sender key distribution that the content
carries, and checks that a managed group context binds to the group of
the transport. It stores no content, decides no group state, and sends
no receipt.

Warning: the decrypt spends the ratchet step. When the application
loses the returned plaintext, no later decrypt of the envelope gives it
again. Use `processIncomingEnvelope`, which keeps the content until the
application completes the receive.

#### Parameters

##### envelope

[`IncomingEnvelope`](IncomingEnvelope.md)

The encrypted message envelope

#### Returns

`Promise`\<\{ `groupContext?`: [`GroupContentContext`](GroupContentContext.md); `plaintext`: `string`; \}\>

The plaintext as its sender gave it, and the group context of
  managed-group content

#### Throws

EncryptionError when the decrypt fails, and INVALID_CIPHERTEXT
  for a `retry_request` envelope, identified or sealed

#### Throws

GroupReceiveRefusedError when the group context is malformed or
  names another group than the transport

***

### decryptFile()

> **decryptFile**(`remoteAddress`, `encryptedBlob`, `encryptedKey`): `Promise`\<`Blob`\>

Decrypt file blob

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### encryptedBlob

`Blob`

Encrypted file data

##### encryptedKey

[`Ciphertext`](../type-aliases/Ciphertext.md)

Encrypted file key

#### Returns

`Promise`\<`Blob`\>

#### Throws

EncryptionError with `BINARY_BLOB_UNAVAILABLE` when the runtime's
`Blob` cannot hold bytes, as on React Native. The key message stays
unconsumed. Use `streamingDecrypt` from `@open-e2ee/signal-protocol-sdk/files`
there.

***

### ~~decryptGroupMessage()~~

> **decryptGroupMessage**(`groupId`, `senderId`, `senderDeviceId`, `framedMessage`): `Promise`\<`string`\>

Decrypt a group message from a sender

The message passes the group decision of `processIncomingEnvelope`.
Content whose group state must update first stays stored, and a later
call with the same message decides it with no second decrypt.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender's user ID

##### senderDeviceId

`number`

Sender's device ID

##### framedMessage

`Uint8Array`

Framed SenderKeyMessage bytes

#### Returns

`Promise`\<`string`\>

Decrypted plaintext

#### Deprecated

Use `processIncomingEnvelope`, which returns a receive
  outcome and keeps the content until the application completes the
  receive. This method completes the receive before it returns, so a
  plaintext that the application loses is gone.

#### Throws

GroupReceiveUnavailableError when the group state of the content
  is not current. Its `messageId` names the stored receive. Call again
  later with the same message.

#### Throws

GroupReceiveRefusedError when the client refuses the content

***

### decryptMessage()

> **decryptMessage**(`remoteAddress`, `ciphertext`): `Promise`\<`string`\>

Decrypt a message from a remote address

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### ciphertext

[`Ciphertext`](../type-aliases/Ciphertext.md)

Message to decrypt

#### Returns

`Promise`\<`string`\>

***

### deleteGroupSenderKey()

> **deleteGroupSenderKey**(`groupId`): `Promise`\<`void`\>

Delete sender key when leaving a group

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<`void`\>

***

### deleteRemoteAttachment()

> **deleteRemoteAttachment**(`attachment`, `options?`): `Promise`\<`void`\>

Delete the encrypted remote object referenced by an attachment pointer.

This only touches the remote object store. The application must delete
app-owned local message rows and local media caches.

#### Parameters

##### attachment

[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md)

##### options?

`Pick`\<[`AttachmentTransferOptions`](AttachmentTransferOptions.md), `"signal"` \| `"onProgress"`\>

#### Returns

`Promise`\<`void`\>

***

### deleteSession()

> **deleteSession**(`remoteAddress`): `Promise`\<`void`\>

Delete session (for session reset)

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

#### Returns

`Promise`\<`void`\>

***

### discardPendingReceive()

> **discardPendingReceive**(`messageId`): `Promise`\<[`PendingReceive`](PendingReceive.md) \| `null`\>

Remove one stored receive that the application gives up on, such as a
receive whose `onMessageDecrypted` hook fails at each start. The client
deletes the receive and marks its envelope processed, so a redelivery
of the envelope is a duplicate. The call sends no receipt, calls no
hook, and runs no `onReceiveExpired`. A hook call that already started
for the receive still runs, and no receipt follows it.

#### Parameters

##### messageId

`string`

The `messageId` of a receive that
  `listPendingReceives` lists

#### Returns

`Promise`\<[`PendingReceive`](PendingReceive.md) \| `null`\>

The removed receive, or null when the client removed nothing:
  no listed receive has the ID, or another path wrote the receive during
  the call and again after one read

***

### distributeGroupSenderKey()

> **distributeGroupSenderKey**(`groupId`, `memberUserIds`): `Promise`\<`void`\>

Distribute sender key to all group members

#### Parameters

##### groupId

`string`

Group identifier

##### memberUserIds

`string`[]

Array of all member user IDs

#### Returns

`Promise`\<`void`\>

***

### distributeSenderKeyToUser()

> **distributeSenderKeyToUser**(`groupId`, `recipientUserId`): `Promise`\<`void`\>

Distribute sender key to a specific user via pairwise encryption

#### Parameters

##### groupId

`string`

Group identifier

##### recipientUserId

`string`

Recipient user ID to distribute key to

#### Returns

`Promise`\<`void`\>

***

### downloadAttachment()

> **downloadAttachment**(`attachment`, `options?`): `Promise`\<[`ResolvedMediaAttachment`](../namespaces/media/interfaces/ResolvedMediaAttachment.md)\>

Download, verify, and decrypt an uploaded attachment pointer.

The client validates pointer metadata, verifies the encrypted blob digest,
and only returns plaintext after streaming AEAD authentication succeeds.

#### Parameters

##### attachment

[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md)

##### options?

[`AttachmentTransferOptions`](AttachmentTransferOptions.md)

#### Returns

`Promise`\<[`ResolvedMediaAttachment`](../namespaces/media/interfaces/ResolvedMediaAttachment.md)\>

***

### encryptFile()

> **encryptFile**(`remoteAddress`, `fileBlob`, `mimeType?`): `Promise`\<\{ `encryptedBlob`: `Blob`; `encryptedKey`: [`Ciphertext`](../type-aliases/Ciphertext.md); `keyId`: `string`; \}\>

Encrypt file blob with two-layer encryption
Returns encrypted blob and encrypted key

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### fileBlob

`Blob`

File data to encrypt

##### mimeType?

`string`

Optional MIME type for the file

#### Returns

`Promise`\<\{ `encryptedBlob`: `Blob`; `encryptedKey`: [`Ciphertext`](../type-aliases/Ciphertext.md); `keyId`: `string`; \}\>

#### Throws

EncryptionError with `BINARY_BLOB_UNAVAILABLE` when the runtime's
`Blob` cannot hold bytes, as on React Native. Use `streamingEncrypt` from
`@open-e2ee/signal-protocol-sdk/files` there.

***

### encryptGroupMessage()

> **encryptGroupMessage**(`groupId`, `plaintext`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Encrypt a message for group using sender key (O(1) encryption)

#### Parameters

##### groupId

`string`

Group identifier

##### plaintext

`string`

Message to encrypt

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Framed SenderKeyMessage bytes

***

### encryptMessage()

> **encryptMessage**(`remoteAddress`, `plaintext`): `Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)\>

Encrypt a message for a remote address

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### plaintext

`string`

Message to encrypt

#### Returns

`Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)\>

***

### establishSession()

> **establishSession**(`remoteAddress`, `prekeyBundle`): `Promise`\<`void`\>

Establish a new session using remote party's prekey bundle

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### prekeyBundle

[`RelayPreKeyBundle`](RelayPreKeyBundle.md)

Remote party's prekey bundle from server

#### Returns

`Promise`\<`void`\>

***

### forgetSentContent()

> **forgetSentContent**(`clientMessageId`): `Promise`\<`boolean`\>

Delete the resendable content of one group send.

The client keeps the content of a resendable group send to answer a
retry request, until each recipient device confirms it with an E2EE
delivery receipt or the retention ends. Call this method when the
application deletes the message, so a later retry request gets no
content. The method does not delete pairwise message records.

#### Parameters

##### clientMessageId

`string`

The `clientMessageId` of the send

#### Returns

`Promise`\<`boolean`\>

True when the client held content for the send

***

### getGroupSenderKeyDistribution()

> **getGroupSenderKeyDistribution**(`groupId`): `Promise`\<[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md) \| `null`\>

Get the current sender key distribution message for a group

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md) \| `null`\>

Distribution message or null if no key exists

***

### getPendingRecipients()

> **getPendingRecipients**(`clientMessageId`): `Promise`\<`SendLogDevice`[]\>

The recipient devices of a resendable group send that have not
confirmed it with an E2EE delivery receipt.

A device leaves the list when its E2EE delivery receipt arrives. A Relay
delivery receipt does not remove it, because a device also acknowledges
a copy that it could not decrypt. The list is empty after the retention
ends, after `forgetSentContent`, and for a send that the client did not
log.

#### Parameters

##### clientMessageId

`string`

The `clientMessageId` of the send

#### Returns

`Promise`\<`SendLogDevice`[]\>

***

### getSessionHealth()

> **getSessionHealth**(`userId`): `Promise`\<[`SessionHealthResult`](SessionHealthResult.md)\>

Get health status for encryption sessions with a specific user.

Checks session existence, key validity, key freshness, and expiration.
This is a client-side check that does not require server calls.

#### Parameters

##### userId

`string`

The user ID to check session health for

#### Returns

`Promise`\<[`SessionHealthResult`](SessionHealthResult.md)\>

SessionHealthResult with status and detailed diagnostics

***

### handleGroupMembershipChange()

> **handleGroupMembershipChange**(`groupId`, `change`): `Promise`\<\{ `distributionMessage?`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `rotated`: `boolean`; \}\>

Handle group membership change with appropriate sender key actions

#### Parameters

##### groupId

`string`

Group identifier

##### change

`"member_added"` \| `"member_removed"` \| `"metadata_changed"`

Type of membership change

#### Returns

`Promise`\<\{ `distributionMessage?`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `rotated`: `boolean`; \}\>

Distribution message if rotation occurred

***

### hasGroupSenderKey()

> **hasGroupSenderKey**(`groupId`): `Promise`\<`boolean`\>

Check if we have a sender key for a group

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<`boolean`\>

True if sender key exists

***

### hasSession()

> **hasSession**(`remoteAddress`): `Promise`\<`boolean`\>

Check if a session exists for a remote address

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

#### Returns

`Promise`\<`boolean`\>

***

### listPendingReceives()

> **listPendingReceives**(`query?`): `Promise`\<\{ `items`: [`PendingReceive`](PendingReceive.md)[]; `next?`: `string`; \}\>

List the stored receives in arrival order, one page at a time. A receive
whose content the application has, and whose receipt waits, is not
listed.

#### Parameters

##### query?

`ready` lists only the helper receives whose content
  waits for `completeReceive`. `after` is the `next` value of the page
  before. `limit` is the page size, 100 by default.

###### after?

`string`

###### limit?

`number`

###### ready?

`boolean`

#### Returns

`Promise`\<\{ `items`: [`PendingReceive`](PendingReceive.md)[]; `next?`: `string`; \}\>

The page, and `next` when a later page can follow

#### Throws

Error when `after` is not a `next` value or `limit` is not a
  positive integer

***

### processGroupSenderKeyDistribution()

> **processGroupSenderKeyDistribution**(`groupId`, `senderId`, `senderDeviceId`, `message`): `Promise`\<`void`\>

Process a sender key distribution message from another group member

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender's user ID

##### senderDeviceId

`number`

Sender's device ID

##### message

[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md)

Distribution message containing the sender key

#### Returns

`Promise`\<`void`\>

***

### processIncomingEnvelope()

> **processIncomingEnvelope**(`envelope`, `options?`): `Promise`\<[`ReceiveOutcome`](../type-aliases/ReceiveOutcome.md)\>

Process an incoming encrypted message envelope.

The receive helper for an application that pulls envelopes itself. It
decrypts the envelope and commits its content as a receive record with
the ratchet step, then decides the group of the content. Handles
decryption and automatically sends SESAME retry requests on retryable
failures. The content stays recoverable until the application calls
`completeReceive`, or until `onPersist` resolves.

The outcome tells the caller what to do with the envelope:

- `processed`: give the content to the application, then acknowledge
  the envelope. A redelivery of the envelope before `completeReceive`
  returns the same outcome again with no second decrypt. A second
  `completeReceive` is a no-op.
- `pending`: the content is stored and the client resumes it, for
  example when its group state must update first. Acknowledge the
  envelope. When the group updates, the client decides the content
  again, and `listPendingReceives({ ready: true })` then lists it.
- `duplicate`: this client processed the envelope, or the application
  already has the content of the failed envelope of a retry request.
  The client acknowledged the envelope.
- `null-message`: the envelope carries no content. The client consumes
  a null message when the content adapter reports `nullMessage: true`,
  and a custom adapter must report it for its own null encoding. The
  client acknowledged it. A null message for a failed envelope marks
  that envelope processed, so a redelivery of it is dropped, but a
  content resend for it that comes later still gives its content.
- `denied`: the client refused the content. The ratchet step is spent,
  so no resend can repair it. `onDecryptionError` ran, except for a
  group that the user blocked (reason `blocked`), which has no report.
  The client acknowledged the envelope. Content from another account that carries
  a sync message is denied in any envelope.
- `refused`: the receive queue has no room. Nothing is decrypted or
  stored. Do not acknowledge the envelope. Give it again later.

The stored receives count toward `protocol.receiveQueue` and expire
after 30 days, with `onReceiveExpired`.

A group message that fails with a retryable error gets a retry request
and is acknowledged, as a pairwise message is. A message with the
Implicit content hint gets no request and is acknowledged.

A retry request follows the sealed sender delivery mode. With a relay
and the access key of the sender, the client posts it sealed. Otherwise
the client posts it identified only when the mode permits it. In
`'required'` mode a retry request that cannot be sealed is not posted:
it stays pending until its deadline. The `sendRetryRequest` callback
gets an identified envelope, so the client calls it only when the mode
permits identified delivery.

A `retry_request` envelope holds no plaintext. This method rejects it,
identified or sealed, and sends no retry request. Give it to
`receiveIncomingEnvelopes`, which handles it.

A failed envelope that this client asked a resend for, and each resend
or null message for it, gives content at most once on both receive
paths.

A resend that brings only the sender key of a failed group message
gives no content. It does not mark the failed envelope processed, so a
redelivery of that envelope decrypts with the key. A resend that brings
the content beside the key gives that content and marks the failed
envelope processed.

A resend or null message that fails to decrypt, or whose seal fails to
open, asks again for its failed envelope under the same retry ID. When
the processed record of the failed envelope fails to store after a
decrypt, the client writes a warning with the behavior
RETRY_FULFILL_WRITE_FAILED, as on every receive path, and this method
still returns the outcome. A redelivery of the failed envelope or of
another family member can then give the content again. When a
processed record of a null message or of its failed envelope fails to
store, the client writes a warning with the behavior
RETRY_NULL_WRITE_FAILED, as on every receive path, and this method
still returns `null-message`. A redelivery of the failed envelope can
then give the content.

This method never throws `GroupResendDeferredError`, because it
rejects a retry request.
`receiveIncomingEnvelopes` reports a deferred retry request in
`failedMessageIds`, so the Relay keeps the request.

#### Parameters

##### envelope

[`IncomingEnvelope`](IncomingEnvelope.md)

The encrypted message envelope

##### options?

[`ProcessEnvelopeOptions`](ProcessEnvelopeOptions.md)

Transport callbacks for background (no relay)
  scenarios, and `onPersist`

#### Returns

`Promise`\<[`ReceiveOutcome`](../type-aliases/ReceiveOutcome.md)\>

The receive outcome

#### Throws

EncryptionError after sending retry request if decryption fails

#### Throws

EncryptionError INVALID_CIPHERTEXT for a `retry_request` envelope,
  identified or sealed

#### Example

```typescript
const outcome = await signal.processIncomingEnvelope(envelope, {
  // Background (the client has no relay)
  sendRetryRequest: async (envelope) => {
    // Post the retry_request envelope like any other envelope.
    await backgroundRelay.send(envelope);
  },
  // The client completes the receive when the content is stored.
  onPersist: (processed) => db.saveMessage(processed.messageId, processed.plaintext),
});
if (outcome.kind !== 'refused') await backgroundRelay.acknowledge(envelope.id);
```

***

### processPendingReceives()

> **processPendingReceives**(`options?`): `Promise`\<\{ `processed`: `number`; `remaining`: `number`; \}\>

Run one pass of the receive queue now, and stop between records at the
deadline. A host that wakes for a push calls it after it acknowledged
the pulled envelopes.

#### Parameters

##### options?

`deadlineMs` bounds the pass. With no deadline, the
  pass runs until each record is handled.

###### deadlineMs?

`number`

#### Returns

`Promise`\<\{ `processed`: `number`; `remaining`: `number`; \}\>

The receives that the pass handled, and the receives that
  still wait

***

### registerHook()

> **registerHook**(`name`, `callback`): `void`

Register an event hook for Signal Protocol events

Allows post-construction hook registration for flexibility.
Useful when the app needs to construct storage or content services after the
Signal Protocol client exists.

#### Parameters

##### name

`string`

Hook name

##### callback

(...`args`) => `void` \| `Promise`\<`void`\>

Hook callback function

#### Returns

`void`

#### Example

```typescript
signal.registerHook('onMessageDecrypted', async (envelope) => {
  await contentManager.storeMessage(envelope);
});
```

***

### resendMessage()

> **resendMessage**(`clientMessageId`): `Promise`\<[`SendResult`](SendResult.md)\>

Post a send again, as a new message, after it ended at its posting
deadline without acceptance.

Call it only for a send whose `send()` threw `SendAcceptanceUnknownError`
or `SendNeverAcceptedByRelayError`, or whose `onSendOutcome` event gave
`failed` or `acceptance-unknown`. The resend keeps the `clientMessageId`,
the client timestamp and the content of the send. It encrypts the
content again for each recipient device that the Relay did not accept,
and posts each copy under the message ID `<clientMessageId>:manual:N`,
N from 1. The receive queue of a recipient device that already holds
the message drops the copy by its sender device, its client timestamp
and its content. The drop needs the timestamp that the content adapter
reads from the message. Content with no timestamp, such as raw string or
byte content, takes no drop key, and a recipient that holds it receives
the copy again. The recipient records the message with the completion
of its receive record, or, when a receipt is due, right after the
receipt-due write and again with the completion of the receipt. The
record expires after 60 days. The caller-origin receive path gives every
decrypted message to the caller, and a caller that keeps its own records
removes a copy itself.

Only a send younger than 30 days takes a new resend. An open resend of
an older send still posts until its own deadline.

The resend is a new Relay operation with its own operation epoch, so the
Relay can charge a resend as a new message. It has its own posting
deadline, 24 hours after the call. Until that deadline, a later call
posts the same resend again, and the SDK send driver posts it again
after a restart. At the deadline it ends: `onSendOutcome` reports its end
once, with `manualResend` set. With `acceptance-unknown`, the resend
might have arrived.

The content must still be stored: the message record of the send, or
its send log entry for a resendable group send. A resend of a group send
posts the content of its send log entry, so each copy carries the group
context of the original send, not the current one.

#### Parameters

##### clientMessageId

`string`

The `clientMessageId` of the send

#### Returns

`Promise`\<[`SendResult`](SendResult.md)\>

The result of the resend when the Relay accepted each device

#### Throws

SendAcceptanceUnknownError or SendNeverAcceptedByRelayError when
  the resend ends at its posting deadline

#### Throws

Error when the send is unknown, still open or completed, when
  the Relay accepted each recipient device, when the content is gone, or
  when the send is 30 days old or older and has no open resend

***

### rotateAccountIdentity()

> **rotateAccountIdentity**(`expectedCurrentCommitment`, `identityType?`): `Promise`\<`void`\>

Explicitly rotate the account-level relay identity with compare-and-swap.

#### Parameters

##### expectedCurrentCommitment

`Uint8Array`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`void`\>

***

### rotateGroupSenderKey()

> **rotateGroupSenderKey**(`groupId`): `Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Rotate sender key for a group (forward secrecy on membership changes)

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

New sender key ID and distribution message

***

### rotatePreKeys()

> **rotatePreKeys**(): `Promise`\<[`PreKeyRotationResult`](PreKeyRotationResult.md)\>

Rotate the device's prekeys in one publication.

One inventory read decides whether the EC signed prekey, the KEM
last-resort prekey, or a one-time prekey batch is due. Signed keys rotate
once they are older than the configured refresh interval
([KEY\_REFRESH\_INTERVAL\_MS\_DEFAULT](../variables/KEY_REFRESH_INTERVAL_MS_DEFAULT.md), 2 days by default). One-time
prekeys refill when a server count is below the threshold. Nothing due
costs one read and no publication, so the method is safe to call often.

#### Returns

`Promise`\<[`PreKeyRotationResult`](PreKeyRotationResult.md)\>

***

### send()

> **send**(`recipientId`, `content`, `options?`): `Promise`\<[`SendResult`](SendResult.md)\>

Send content to a recipient

This is the primary API for sending encrypted content.
Automatically handles:
- Group vs user detection (Signal Protocol V2 prefix)
- Content type routing (DataMessageInput, string, Uint8Array)
- Multi-device fan-out
- Sender key distribution for groups

#### Parameters

##### recipientId

`string`

Prefixed group ID or userId for direct messages

##### content

`string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`DataMessageInput`](DataMessageInput.md)

DataMessageInput, string, or raw Uint8Array bytes

##### options?

[`SendOptions`](SendOptions.md)

Optional send options

#### Returns

`Promise`\<[`SendResult`](SendResult.md)\>

SendResult with messageId, timestamp, recipientDeviceCount

#### Example

```typescript
import { createGroupId } from '@open-e2ee/signal-protocol-sdk';

// Send to group (use createGroupId helper)
await signal.send(createGroupId(groupId), content);

// Send to user
await signal.send(userId, content);

// Send raw bytes
await signal.send(recipient, new Uint8Array([...]));
```

***

### sendReadReceipt()

> **sendReadReceipt**(`recipientUserId`, `timestamps`): `Promise`\<`void`\>

Send read receipt to original message sender (all devices)

Called when the user views messages in a conversation.
Similar to delivery receipts but indicates message was actually read.
Multi-device: fans out to all known devices for the sender.

#### Parameters

##### recipientUserId

`string`

Original sender's user ID

##### timestamps

`number`[]

Server timestamps of the messages the user read

#### Returns

`Promise`\<`void`\>

***

### sendTypingIndicator()

> **sendTypingIndicator**(`recipientUserId`, `recipientDeviceId`, `conversationId`, `action`, `groupId?`): `Promise`\<`void`\>

Send typing indicator to conversation recipient

Typing indicators are application-layer messages that:
- Use the same encrypted channel as regular messages
- Are NOT stored on the server (transient)
- Respect privacy settings (mutual opt-in required)

#### Parameters

##### recipientUserId

`string`

Recipient's user ID

##### recipientDeviceId

`number`

Recipient's device ID

##### conversationId

`string`

The conversation ID

##### action

[`TypingAction`](../enumerations/TypingAction.md)

Whether user STARTED or STOPPED typing

##### groupId?

`string`

Optional group ID for group conversations

#### Returns

`Promise`\<`void`\>

***

### sendViewedReceipt()

> **sendViewedReceipt**(`recipientUserId`, `timestamps`): `Promise`\<`void`\>

Send viewed receipt to original message sender (all devices).

Used for content where "opened" matters semantically, such as view-once
attachments. This follows the same privacy gate as read receipts.

#### Parameters

##### recipientUserId

`string`

##### timestamps

`number`[]

#### Returns

`Promise`\<`void`\>

***

### startRelaySubscription()

> **startRelaySubscription**(): `void`

Start the relay subscription for receiving encrypted messages.

Startup is explicit so applications can register hooks before delivery
starts. A call while `stop()` runs is refused and logged; start again
after `stop()` resolves.

#### Returns

`void`

***

### stop()

> **stop**(): `Promise`\<`void`\>

Stop the client and cleanup resources

Call this on logout or app shutdown. It first sends each delivery
receipt batch that waits, once. Then it waits for delivery receipt
sends, including their app hooks, until one deadline 5 s after `stop()`
starts. It waits for each receipt send that is in progress when `stop()`
starts, except a send that an earlier `stop()` stopped, and for the
sends that it starts. A delivery that finishes during the wait batches
its receipt. At the end of each wait, `stop()` sends the batches that
wait and waits for those sends until the same deadline. It does this
again while the deadline is not past. `stop()` holds the receipt batches
from its first flush until it clears its tracking state. During the
hold, `stopRelaySubscription()` does not send them, and `stop()` drops a
receipt batched after its last flush. At the deadline it stops each
receipt send that is left: a send that waits in an app hook stops, and
that receipt is not sent. A send that is in its relay call at the
deadline is waited for, and that receipt can still be sent. It also
resolves after the SDK work of the relay deliveries and retry requests
in progress finishes. Apart from the receipt wait, it does not wait for
app hooks, so a hook can await `stop()`. A hook of a delivery receipt
send that awaits `stop()` holds `stop()` until the deadline. `stop()`
does not wait for read and viewed receipt sends. When a hook returns
after `stop()`, the SDK drops the work after the hook and writes nothing
more. The relay delivers the envelope again after the next start.

A call to `startRelaySubscription()` while `stop()` runs is refused and
logged; start again after `stop()` resolves. A `stop()` call that
overlaps a running `stop()` waits for it and settles as it settles.

#### Returns

`Promise`\<`void`\>

***

### stopRelaySubscription()

> **stopRelaySubscription**(): `void`

Stop the relay subscription

Pauses message processing without destroying client state. It first
starts the send of the delivery receipts that wait in a batch. `stop()`
holds the receipt batches from its first flush until it clears its
tracking state. During the hold, `stopRelaySubscription()` does not send
them. `stop()` sends the batches that wait at each of its flushes and
drops a batch made during the hold after its last flush.
Use when app backgrounds to let background task handle messages.
Call startRelaySubscription() to resume when app foregrounds.
`bindRelayLifecycle` and the `useRelayLifecycle` hook make both calls
from the app state.

#### Returns

`void`

***

### subscribeRelayConnectionState()

> **subscribeRelayConnectionState**(`listener`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Subscribe to relay connection transitions.

The listener receives each new state once. Read `relayConnectionState` for
the current state.

#### Parameters

##### listener

(`state`) => `void`

Callback for each transition

#### Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)

Unsubscribe function

***

### syncBlockedRecipientsToLinkedDevices()

> **syncBlockedRecipientsToLinkedDevices**(`blocked`): `Promise`\<`void`\>

Sync the current blocked-recipient snapshot to linked devices.

The full current snapshot replaces the local linked-device projection
instead of applying deltas.

The `syncedAt` time is the epoch of the sync. The SDK accepts a safe positive
integer at most 5 minutes ahead of the SDK clock and at most 24 hours
behind it, and throws `InvalidSendTimestampError` for any other value
before it posts.

#### Parameters

##### blocked

[`BlockedRecipientsSyncInput`](BlockedRecipientsSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncConfigurationToLinkedDevices()

> **syncConfigurationToLinkedDevices**(`configuration`): `Promise`\<`void`\>

Sync account-level communication/privacy configuration to linked devices.

This holds linked-device state, not a sender-facing receipt. It should carry
the current local snapshot for supported fields.

#### Parameters

##### configuration

[`ConfigurationSyncInput`](ConfigurationSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncMediaAttachmentDeleteToLinkedDevices()

> **syncMediaAttachmentDeleteToLinkedDevices**(`entry`): `Promise`\<`void`\>

Sync a local media attachment delete event to the account's other linked devices.

This is account-local device state, not a sender-facing receipt. The app
remains responsible for applying the delete to its local media cache.

The `deletedAt` time is the epoch of the sync. The SDK accepts a safe positive
integer at most 5 minutes ahead of the SDK clock and at most 24 hours
behind it, and throws `InvalidSendTimestampError` for any other value
before it posts.

#### Parameters

##### entry

[`MediaAttachmentDeleteSyncInput`](MediaAttachmentDeleteSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncReadToLinkedDevices()

> **syncReadToLinkedDevices**(`entries`): `Promise`\<`void`\>

Sync local read state to the account's other linked devices.

This is separate from read receipts: it updates our own devices so they
stay in sync even when the configuration disables remote read receipts.

#### Parameters

##### entries

[`ReadSyncEntryInput`](ReadSyncEntryInput.md)[]

#### Returns

`Promise`\<`void`\>

***

### syncRecipientUsernameToLinkedDevices()

> **syncRecipientUsernameToLinkedDevices**(`recipientUsername`): `Promise`\<`void`\>

Sync learned recipient username metadata to linked devices.

Remote usernames are transient lookup data, but once learned on one device
they should be available on the account's other linked devices.

The `learnedAt` time is the epoch of the sync. The SDK accepts a safe positive
integer at most 5 minutes ahead of the SDK clock and at most 24 hours
behind it, and throws `InvalidSendTimestampError` for any other value
before it posts.

#### Parameters

##### recipientUsername

[`RecipientUsernameSyncInput`](RecipientUsernameSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncTaskNotificationAckToLinkedDevices()

> **syncTaskNotificationAckToLinkedDevices**(`input`): `Promise`\<`void`\>

Sync task-notification acknowledgment state to the account's other linked devices.

This is app-level linked-device notification state, not sender-facing content.

The `acknowledgedAt` time is the epoch of the sync. The SDK accepts a safe positive
integer at most 5 minutes ahead of the SDK clock and at most 24 hours
behind it, and throws `InvalidSendTimestampError` for any other value
before it posts.

#### Parameters

##### input

`Omit`\<[`TaskNotificationAckSyncInput`](TaskNotificationAckSyncInput.md), `"acknowledgedOnDevice"`\>

#### Returns

`Promise`\<`void`\>

***

### syncUsernameStateToLinkedDevices()

> **syncUsernameStateToLinkedDevices**(`usernameState`): `Promise`\<`void`\>

Sync local username and username-link state to linked devices.

This is account-local state, not sender-facing content.

#### Parameters

##### usernameState

[`UsernameStateSyncInput`](UsernameStateSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncVerificationStateToLinkedDevices()

> **syncVerificationStateToLinkedDevices**(`verificationState`): `Promise`\<`void`\>

Sync explicit safety-number verification state to the account's other linked devices.

Only explicit `verified` and cleared-to-`default` states belong here.
Conflict and untrusted state is still derived locally from identity-key changes.

The `changedAt` time is the epoch of the sync. The SDK accepts a safe positive
integer at most 5 minutes ahead of the SDK clock and at most 24 hours
behind it, and throws `InvalidSendTimestampError` for any other value
before it posts.

#### Parameters

##### verificationState

[`VerificationStateSyncInput`](VerificationStateSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncViewOnceOpenToLinkedDevices()

> **syncViewOnceOpenToLinkedDevices**(`entry`): `Promise`\<`void`\>

Sync a local view-once open event to the account's other linked devices.

This is account-local device state, not a sender-facing receipt.

#### Parameters

##### entry

[`ViewOnceOpenSyncInput`](ViewOnceOpenSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### uploadAttachment()

> **uploadAttachment**(`data`, `options`): `Promise`\<[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md)\>

Encrypt and upload an attachment without sending a standalone message.

Used by higher-level content types that want to carry attachment metadata
atomically inside another message payload.

#### Parameters

##### data

`Uint8Array`

##### options

[`SendOptions`](SendOptions.md) & `object`

#### Returns

`Promise`\<[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md)\>
