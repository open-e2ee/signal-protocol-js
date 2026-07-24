[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISignalProtocolClient

# Interface: ISignalProtocolClient

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

### deviceId

> `readonly` **deviceId**: `number`

Device ID for this client instance (1 = primary, 2-5 = linked)

***

### logger

> `readonly` **logger**: `Required`\<[`ILogger`](ILogger.md)\>

Resolved logger for this client instance.

This is the client-scoped logger used throughout the Signal runtime.

***

### userId

> `readonly` **userId**: `string`

User ID for this client instance

## Methods

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

***

### decryptGroupMessage()

> **decryptGroupMessage**(`groupId`, `senderId`, `senderDeviceId`, `framedMessage`): `Promise`\<`string`\>

Decrypt a group message from a sender

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

This only touches remote object storage. App-owned local message rows and
local media caches must be deleted by the application.

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

### getSessionHealth()

> **getSessionHealth**(`userId`): `Promise`\<[`SessionHealthResult`](SessionHealthResult.md)\>

Get health status for encryption sessions with a specific user.

Checks session existence, key validity, key freshness, and expiration.
This is a client-side check that doesn't require server calls.

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

> **processIncomingEnvelope**(`envelope`, `options?`): `Promise`\<`string`\>

Process an incoming encrypted message envelope.

Unified entry point for both foreground (relay) and background (HTTP) message processing.
Handles decryption and automatically sends SESAME retry requests on retryable failures.

This method:
1. Decodes base64 ciphertext
2. Decrypts message using Double Ratchet
3. On retryable error: sends retry request via relay or options callback
4. Re-throws error for caller to handle

#### Parameters

##### envelope

[`IncomingEnvelope`](IncomingEnvelope.md)

The encrypted message envelope

##### options?

[`ProcessEnvelopeOptions`](ProcessEnvelopeOptions.md)

Transport callbacks for background (no relay) scenarios

#### Returns

`Promise`\<`string`\>

Decrypted plaintext

#### Throws

EncryptionError after sending retry request if decryption fails

#### Example

```typescript
// Foreground (relay available)
const plaintext = await signal.processIncomingEnvelope(envelope);

// Background (no relay)
const plaintext = await signal.processIncomingEnvelope(envelope, {
  sendRetryRequest: async (req) => {
    await convex.mutation(api.signal.messages.sendRetryRequest, req);
  }
});
```

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

### rotateAccountIdentity()

> **rotateAccountIdentity**(`expectedCurrentCommitment`, `identityType?`): `Promise`\<`void`\>

Explicit compare-and-swap rotation of the account-level relay identity.

#### Parameters

##### expectedCurrentCommitment

`Uint8Array`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`void`\>

***

### rotateEcSignedPreKey()

> **rotateEcSignedPreKey**(): `Promise`\<`boolean`\>

Rotate EC signed prekey

Should be called weekly to maintain forward secrecy.
Returns false if rotation is not needed yet.

#### Returns

`Promise`\<`boolean`\>

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

### rotateKyberPreKey()

> **rotateKyberPreKey**(): `Promise`\<`boolean`\>

Rotate Kyber prekey (post-quantum)

Should be called weekly alongside signed prekey rotation.
Returns false if rotation is not needed yet.

#### Returns

`Promise`\<`boolean`\>

***

### runPeriodicCleanup()

> **runPeriodicCleanup**(): `number`

Run periodic cleanup of internal tracking state.

Safe to call frequently - internally throttled to avoid overhead.
Recommended call sites:
- App foreground transition
- After successful message batch processing
- Periodically during long sessions

Cleans up:
- Expired retry dedup entries (recentRetryRequests)

#### Returns

`number`

Number of entries cleaned up

***

### send()

> **send**(`recipientId`, `content`, `options?`): `Promise`\<[`SendResult`](SendResult.md)\>

Send content to a recipient

This is the primary API for sending encrypted content.
Automatically handles:
- Group vs user detection (Signal V2 prefix)
- Content type routing (DataMessageInput, string, Uint8Array)
- Multi-device fan-out
- Sender key distribution for groups

#### Parameters

##### recipientId

`string`

Group ID with V2 prefix or userId for direct messages

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

Server timestamps of messages that were read

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
begins.

#### Returns

`void`

***

### stop()

> **stop**(): `Promise`\<`void`\>

Stop the client and cleanup resources

Should be called on logout or app shutdown.

#### Returns

`Promise`\<`void`\>

***

### stopRelaySubscription()

> **stopRelaySubscription**(): `void`

Stop the relay subscription

Pauses message processing without destroying client state.
Use when app backgrounds to let background task handle messages.
Call startRelaySubscription() to resume when app foregrounds.

#### Returns

`void`

***

### syncBlockedRecipientsToLinkedDevices()

> **syncBlockedRecipientsToLinkedDevices**(`blocked`): `Promise`\<`void`\>

Sync the current blocked-recipient snapshot to linked devices.

The full current snapshot replaces the local linked-device projection
instead of applying deltas.

#### Parameters

##### blocked

[`BlockedRecipientsSyncInput`](BlockedRecipientsSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncConfigurationToLinkedDevices()

> **syncConfigurationToLinkedDevices**(`configuration`): `Promise`\<`void`\>

Sync account-level communication/privacy configuration to linked devices.

This is linked-device state, not a sender-facing receipt. It should carry
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
stay in sync even when remote read receipts are disabled.

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

Only explicit `verified` and cleared-to-`default` states belong here;
conflict/untrusted state is still derived locally from identity-key changes.

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
