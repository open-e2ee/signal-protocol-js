[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DefaultSignalProtocolClient

# Class: DefaultSignalProtocolClient

Modern Signal Protocol Client

Provides a clean, testable, and flexible API for Signal Protocol operations.
Uses static factory pattern for type-safe async initialization:
- Guaranteed initialization via create() method
- Dependency injection support
- Configuration object pattern
- Clear error handling
- Type-safe API

This client implements the SignalProtocolClient interface and wraps
DefaultSignalProtocolManager with additional high-level functionality.

## Implements

- [`SignalProtocolClient`](../interfaces/SignalProtocolClient.md)

## Properties

### deviceId

> `readonly` **deviceId**: `number`

Device ID for this client instance (1 = primary, 2-5 = linked)

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`deviceId`](../interfaces/SignalProtocolClient.md#deviceid)

***

### logger

> `readonly` **logger**: `Required`\<[`Logger`](../interfaces/Logger.md)\>

Resolved logger for this client instance.

This is the client-scoped logger used throughout the Signal Protocol runtime.

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`logger`](../interfaces/SignalProtocolClient.md#logger)

***

### media

> `readonly` **media**: [`SignalProtocolClientMedia`](../interfaces/SignalProtocolClientMedia.md)

Durable media job facade backed by the configured Signal Protocol local store.

Use this for background-safe attachment uploads, downloads, and cleanup
when the app provides media lifecycle callbacks in `config.media`.

## Accessors

### isSealedSenderEnabled

#### Get Signature

> **get** **isSealedSenderEnabled**(): `boolean`

Whether the client enables and configures sealed sender.

##### Returns

`boolean`

***

### syncStatus

#### Get Signature

> **get** **syncStatus**(): `"synced"` \| `"failed"` \| `"none"`

##### Returns

`"synced"` \| `"failed"` \| `"none"`

***

### userId

#### Get Signature

> **get** **userId**(): `string`

Get user ID for this client instance

##### See

SignalProtocolClient.userId

##### Returns

`string`

User ID for this client instance

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`userId`](../interfaces/SignalProtocolClient.md#userid)

## Methods

### acceptGroupMemberInvitation()

> **acceptGroupMemberInvitation**(`groupId`): `Promise`\<`void`\>

Accept this client's pending profile-key invitation.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

#### Returns

`Promise`\<`void`\>

***

### acceptIdentityRotation()

> **acceptIdentityRotation**(`userId`, `identity`, `identityType?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Accept an authenticated composite-identity rotation and reset bound sessions.

#### Parameters

##### userId

`string`

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md) = `'aci'`

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

***

### addGroupMember()

> **addGroupMember**(`groupId`, `editorAci`, `member`): `Promise`\<`void`\>

Add a member to a group.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

##### member

[`GroupMemberInput`](../type-aliases/GroupMemberInput.md)

#### Returns

`Promise`\<`void`\>

***

### address()

> **address**(): [`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Get the ProtocolAddress for this client's device.

Useful when an integration needs to reference the local device.

#### Returns

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

ProtocolAddress for this client (userId:deviceId)

#### Example

```typescript
const alice = await DefaultSignalProtocolClient.create('alice', { storage: aliceStorage });
const bob = await DefaultSignalProtocolClient.create('bob', { storage: bobStorage });

// Use address() to reference the local device
await alice.encryptMessage(bob.address(), 'Hello');
await bob.decryptMessage(alice.address(), encrypted);

// Access userId if needed
console.log(alice.address().userId); // 'alice'
```

***

### archiveSession()

> **archiveSession**(`remoteAddress`): `Promise`\<`void`\>

Archive a session after a stale-device response.

Moves current session to inactive list, preserving it for delayed message decryption.
Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"

Use this when handling stale device errors (410). The old session may still
decrypt messages that were in-flight during the session refresh.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

#### Returns

`Promise`\<`void`\>

***

### checkPreKeyStatus()

> **checkPreKeyStatus**(): `Promise`\<[`PreKeyStatusResult`](../interfaces/PreKeyStatusResult.md)\>

Check prekey status and trigger warning if running low

Returns the current prekey count and whether the client needs to replenish.
If config supplies an `onPreKeyLow` callback, the client calls it when
the count drops below the threshold.

#### Returns

`Promise`\<[`PreKeyStatusResult`](../interfaces/PreKeyStatusResult.md)\>

Prekey status with remaining count and replenishment flag

#### Example

```typescript
const status = await signal.checkPreKeyStatus();
if (status.needsReplenishment) {
  // Generate and upload more prekeys
  await backend.replenishPrekeys(userId);
}
```

***

### cleanupExpiredKeys()

> **cleanupExpiredKeys**(`remoteAddress`): `Promise`\<`boolean`\>

Clean up expired message keys for a session

Signal Protocol Section 8.4 recommends deleting message keys older than
one week to avoid excessive storage. This method explicitly triggers cleanup.

Note: Cleanup also happens automatically during encrypt/decrypt operations.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

#### Returns

`Promise`\<`boolean`\>

true if cleanup succeeded, false otherwise

***

### cleanupExpiredSesameSessions()

> **cleanupExpiredSesameSessions**(): `Promise`\<`number`\>

Cleanup expired Sesame sessions

Removes inactive sessions that are older than the configured TTL.
Call this periodically (e.g., daily) to prevent database bloat.

#### Returns

`Promise`\<`number`\>

Number of sessions cleaned up

***

### clearAllData()

> **clearAllData**(): `Promise`\<`void`\>

Clear all encryption data

WARNING: This permanently deletes all keys and sessions.
Use only for local development or when resetting the app.

#### Returns

`Promise`\<`void`\>

***

### confirmSafetyNumber()

> **confirmSafetyNumber**(`confirmation`): `Promise`\<`void`\>

Confirm an authenticated comparison of the currently displayed tuple.

#### Parameters

##### confirmation

[`SafetyNumberConfirmation`](../interfaces/SafetyNumberConfirmation.md)

#### Returns

`Promise`\<`void`\>

***

### createGroup()

> **createGroup**(`creatorAci`, `creatorProfileKey`, `members`, `title`, `options?`): `Promise`\<\{ `groupId`: [`GroupId`](../type-aliases/GroupId.md); `masterKey`: `Uint8Array`; \}\>

Create a new group.

#### Parameters

##### creatorAci

`Uint8Array`

##### creatorProfileKey

`Uint8Array`

##### members

[`GroupMemberInput`](../type-aliases/GroupMemberInput.md)[]

##### title

`string`

##### options?

###### accessControl?

`Partial`\<`AccessControl`\>

###### avatarUrl?

`string`

###### description?

`string`

###### disappearingMessagesDuration?

`number`

#### Returns

`Promise`\<\{ `groupId`: [`GroupId`](../type-aliases/GroupId.md); `masterKey`: `Uint8Array`; \}\>

***

### createGroupInviteLink()

> **createGroupInviteLink**(`groupId`, `editorAci`): `Promise`\<`string`\>

Create an invite link for a group.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

#### Returns

`Promise`\<`string`\>

***

### createGroupSenderKey()

> **createGroupSenderKey**(`groupId`): `Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Create a new sender key for group messaging

Call this when joining a group or when the group needs key rotation.
Distribute the returned message to all group members via pairwise sessions.

#### Parameters

##### groupId

`string`

Unique identifier for the group

#### Returns

`Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Distribution message to share with group members

#### Example

```typescript
// Create sender key when joining a group
const { distributionMessage } = await signal.createGroupSenderKey('group-123');

// Distribute to all members via pairwise encryption
for (const member of groupMembers) {
  const encrypted = await signal.encryptMessage(member.address, JSON.stringify(distributionMessage));
  await sendToMember(member, encrypted);
}
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`createGroupSenderKey`](../interfaces/SignalProtocolClient.md#creategroupsenderkey)

***

### declineGroupMemberInvitation()

> **declineGroupMemberInvitation**(`groupId`, `identity?`): `Promise`\<`void`\>

Decline this account's ACI- or PNI-keyed pending invitation.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### identity?

`"aci"` \| `"pni"`

#### Returns

`Promise`\<`void`\>

***

### decryptFile()

> **decryptFile**(`remoteAddress`, `encryptedBlob`, `encryptedKey`): `Promise`\<`Blob`\>

Decrypt file blob

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### encryptedBlob

`Blob`

Encrypted file data

##### encryptedKey

[`Ciphertext`](../type-aliases/Ciphertext.md)

Encrypted symmetric key

#### Returns

`Promise`\<`Blob`\>

Decrypted file blob with correct MIME type

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`decryptFile`](../interfaces/SignalProtocolClient.md#decryptfile)

***

### decryptFiles()

> **decryptFiles**(`remoteAddress`, `files`): `Promise`\<`Blob`[]\>

Decrypt multiple files in batch

More efficient than calling decryptFile() multiple times.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### files

`object`[]

Array of encrypted file data

#### Returns

`Promise`\<`Blob`[]\>

Array of decrypted file blobs in the same order

***

### decryptGroupMessage()

> **decryptGroupMessage**(`groupId`, `senderId`, `senderDeviceId`, `framedMessage`): `Promise`\<`string`\>

Decrypt a group message from a sender

Use this to decrypt messages from other group members.
You must process the sender's distribution message first.

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

#### Example

```typescript
const plaintext = await signal.decryptGroupMessage(
  'group-123',
  senderId,
  senderDeviceId,
  encryptedMessage
);
console.log('Message:', plaintext);
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`decryptGroupMessage`](../interfaces/SignalProtocolClient.md#decryptgroupmessage)

***

### decryptMessage()

> **decryptMessage**(`remoteAddress`, `ciphertext`): `Promise`\<`string`\>

Decrypt a message from a session

Uses the Double Ratchet algorithm to decrypt ciphertext, handling
out-of-order messages and updating session state.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### ciphertext

[`Ciphertext`](../type-aliases/Ciphertext.md)

Message to decrypt

#### Returns

`Promise`\<`string`\>

Decrypted plaintext

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`decryptMessage`](../interfaces/SignalProtocolClient.md#decryptmessage)

***

### decryptMessages()

> **decryptMessages**(`remoteAddress`, `ciphertexts`): `Promise`\<`string`[]\>

Decrypt multiple messages in batch

More efficient than calling decryptMessage() multiple times.
Handles out-of-order messages correctly.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### ciphertexts

[`Ciphertext`](../type-aliases/Ciphertext.md)[]

Array of messages to decrypt

#### Returns

`Promise`\<`string`[]\>

Array of decrypted plaintexts in the same order

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

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`deleteGroupSenderKey`](../interfaces/SignalProtocolClient.md#deletegroupsenderkey)

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

`Pick`\<[`AttachmentTransferOptions`](../interfaces/AttachmentTransferOptions.md), `"signal"` \| `"onProgress"`\>

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`deleteRemoteAttachment`](../interfaces/SignalProtocolClient.md#deleteremoteattachment)

***

### deleteSession()

> **deleteSession**(`remoteAddress`): `Promise`\<`void`\>

Delete a session

Use this to reset encryption for a session (e.g., after a security incident).
You will need to establish a new session before sending/receiving messages.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`deleteSession`](../interfaces/SignalProtocolClient.md#deletesession)

***

### distributeGroupSenderKey()

> **distributeGroupSenderKey**(`groupId`, `memberUserIds`): `Promise`\<`void`\>

Distribute sender key to all group members.

Called after group creation or after key rotation.
Skips self and sends to all other members via pairwise encryption.

#### Parameters

##### groupId

`string`

Group identifier

##### memberUserIds

`string`[]

Array of all member user IDs

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
// After creating a group
const memberIds = ['alice', 'bob', 'charlie'];
await signal.distributeGroupSenderKey('group-123', memberIds);
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`distributeGroupSenderKey`](../interfaces/SignalProtocolClient.md#distributegroupsenderkey)

***

### distributeSenderKeyToUser()

> **distributeSenderKeyToUser**(`groupId`, `recipientUserId`): `Promise`\<`void`\>

Distribute sender key to a specific user via pairwise encryption.

Distribution messages travel through authenticated, encrypted
pairwise channels.

This method:
1. Gets or creates sender key for this group
2. Encrypts the distribution message using pairwise Signal Protocol
3. Sends via SESAME to all of the recipient's devices

#### Parameters

##### groupId

`string`

Group identifier

##### recipientUserId

`string`

Recipient user ID to distribute key to

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
// Distribute key to a specific user
await signal.distributeSenderKeyToUser('group-123', 'bob');
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`distributeSenderKeyToUser`](../interfaces/SignalProtocolClient.md#distributesenderkeytouser)

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

[`AttachmentTransferOptions`](../interfaces/AttachmentTransferOptions.md)

#### Returns

`Promise`\<[`ResolvedMediaAttachment`](../namespaces/media/interfaces/ResolvedMediaAttachment.md)\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`downloadAttachment`](../interfaces/SignalProtocolClient.md#downloadattachment)

***

### encryptFile()

> **encryptFile**(`remoteAddress`, `fileBlob`, `mimeType?`): `Promise`\<\{ `encryptedBlob`: `Blob`; `encryptedKey`: [`Ciphertext`](../type-aliases/Ciphertext.md); `keyId`: `string`; \}\>

Encrypt file blob with two-layer encryption

Layer 1: Random symmetric key encrypts the file
Layer 2: Signal Protocol encrypts the symmetric key

This allows efficient storage of large files with Signal Protocol key rotation.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### fileBlob

`Blob`

File data to encrypt

##### mimeType?

`string`

Optional MIME type (defaults to fileBlob.type)

#### Returns

`Promise`\<\{ `encryptedBlob`: `Blob`; `encryptedKey`: [`Ciphertext`](../type-aliases/Ciphertext.md); `keyId`: `string`; \}\>

Encrypted blob, key ID, and encrypted key

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`encryptFile`](../interfaces/SignalProtocolClient.md#encryptfile)

***

### encryptFiles()

> **encryptFiles**(`remoteAddress`, `files`): `Promise`\<`object`[]\>

Encrypt multiple files in batch

More efficient than calling encryptFile() multiple times.
Each file gets its own encryption key for granular access control.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### files

`object`[]

Array of file blobs with optional MIME types

#### Returns

`Promise`\<`object`[]\>

Array of encrypted file results in the same order

***

### encryptGroupMessage()

> **encryptGroupMessage**(`groupId`, `plaintext`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Encrypt a message for group using sender key (O(1) encryption)

After creating your sender key and distributing it to members,
use this to encrypt messages. All group members can decrypt
the same ciphertext, making it efficient for large groups.

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

#### Example

```typescript
// Encrypt once, send to all members
const encrypted = await signal.encryptGroupMessage('group-123', 'Hello everyone!');

// Broadcast same ciphertext to all members
for (const member of groupMembers) {
  await sendToMember(member, encrypted);
}
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`encryptGroupMessage`](../interfaces/SignalProtocolClient.md#encryptgroupmessage)

***

### encryptMessage()

> **encryptMessage**(`remoteAddress`, `plaintext`): `Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)\>

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

##### plaintext

`string`

#### Returns

`Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)\>

#### See

MessageOps.encryptMessage

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`encryptMessage`](../interfaces/SignalProtocolClient.md#encryptmessage)

***

### encryptMessages()

> **encryptMessages**(`remoteAddress`, `plaintexts`): `Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)[]\>

Encrypt multiple messages in batch

More efficient than calling encryptMessage() multiple times.
The method runs all operations atomically. If any encryption fails,
it encrypts none of the messages.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

##### plaintexts

`string`[]

Array of messages to encrypt

#### Returns

`Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)[]\>

Array of encrypted ciphertexts in the same order

***

### establishSession()

> **establishSession**(`remoteAddress`, `prekeyBundle`, `recipientIdentityType?`): `Promise`\<`void`\>

Establish a new session with a specific remote device.

Advanced direct-device API. Normal app code can call `send(recipientUserId, content)`.
The client will fetch remote device bundles through the configured relay and
use the selected protocol policy. Direct callers must provide the remote
device's prekey bundle themselves.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Partner's protocol address (userId + deviceId)

##### prekeyBundle

[`RelayPreKeyBundle`](../interfaces/RelayPreKeyBundle.md)

Partner's prekey bundle (fetched from server)

##### recipientIdentityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md) = `'aci'`

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';

const remoteAddress = ProtocolAddress.create('bob', 1);
const bundle = await relay.fetchPreKeyBundle(remoteAddress.userId);
await signal.establishSession(remoteAddress, bundle);
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`establishSession`](../interfaces/SignalProtocolClient.md#establishsession)

***

### fetchSenderCertificate()

> **fetchSenderCertificate**(): `Promise`\<`string`\>

Fetch (or return cached) sender certificate for sealed sender.

Uses the configured certificateProvider or relay.fetchSenderCertificate().
Validates the fetched certificate and caches it until one hour before its
signed expiration.

#### Returns

`Promise`\<`string`\>

Base64-encoded serialized SenderCertificate

#### Throws

if no certificate provider is available

***

### forceCompleteKeyReset()

> **forceCompleteKeyReset**(): `Promise`\<[`ForceKeyResetResult`](../interfaces/ForceKeyResetResult.md)\>

Force complete key reset (development/debugging only).

Delegates to PreKeyOps.forceCompleteKeyReset for implementation.

#### Returns

`Promise`\<[`ForceKeyResetResult`](../interfaces/ForceKeyResetResult.md)\>

***

### getGroupSenderKeyDistribution()

> **getGroupSenderKeyDistribution**(`groupId`): `Promise`\<[`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md) \| `null`\>

Get the current sender key distribution message for a group

If no sender key exists, returns null. Use createGroupSenderKey() first.

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<[`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md) \| `null`\>

Distribution message or null if no key exists

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`getGroupSenderKeyDistribution`](../interfaces/SignalProtocolClient.md#getgroupsenderkeydistribution)

***

### getGroupSenderKeyStats()

> **getGroupSenderKeyStats**(`groupId`, `senderId`, `senderDeviceId`): `Promise`\<\{ `chainIndex`: `number`; `generation`: `number`; `skippedKeysCount`: `number`; \}\>

Get statistics for a group sender key.

Useful for debugging and monitoring group messaging health.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

#### Returns

`Promise`\<\{ `chainIndex`: `number`; `generation`: `number`; `skippedKeysCount`: `number`; \}\>

Stats including chain position, generation, and skipped keys count

#### Example

```typescript
const stats = await signal.getGroupSenderKeyStats('group-123', 'alice', 1);
console.log(`Chain at ${stats.chainIndex}, gen ${stats.generation}`);
console.log(`${stats.skippedKeysCount} skipped keys stored`);
```

***

### getGroupState()

> **getGroupState**(`groupId`): `Promise`\<[`DecryptedGroup`](../interfaces/DecryptedGroup.md)\>

Get decrypted group state (from cache or server).

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

#### Returns

`Promise`\<[`DecryptedGroup`](../interfaces/DecryptedGroup.md)\>

***

### getIdentityPublicKey()

> **getIdentityPublicKey**(): `Promise`\<[`PublicKey`](../type-aliases/PublicKey.md)\>

Get client's identity public key

#### Returns

`Promise`\<[`PublicKey`](../type-aliases/PublicKey.md)\>

Public key for this device's identity

***

### getSesameStats()

> **getSesameStats**(): `Promise`\<[`SesameStats`](../interfaces/SesameStats.md)\>

Get Sesame session statistics (for debugging)

Returns information about users, devices, and sessions.

#### Returns

`Promise`\<[`SesameStats`](../interfaces/SesameStats.md)\>

Session statistics

***

### getSessionHealth()

> **getSessionHealth**(`userId`): `Promise`\<[`SessionHealthResult`](../interfaces/SessionHealthResult.md)\>

Get health status for encryption sessions with a specific user.

Delegates to SessionOps.getSessionHealth for implementation.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<[`SessionHealthResult`](../interfaces/SessionHealthResult.md)\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`getSessionHealth`](../interfaces/SignalProtocolClient.md#getsessionhealth)

***

### getStats()

> **getStats**(): `Promise`\<\{ `hasIdentityKey`: `boolean`; `oneTimePreKeysCount`: `number`; `sessionCount`: `number`; \}\>

Get encryption statistics

#### Returns

`Promise`\<\{ `hasIdentityKey`: `boolean`; `oneTimePreKeysCount`: `number`; `sessionCount`: `number`; \}\>

Statistics about sessions, keys, and usage

***

### handleGroupMembershipChange()

> **handleGroupMembershipChange**(`groupId`, `change`): `Promise`\<\{ `distributionMessage?`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `rotated`: `boolean`; \}\>

Handle group membership change with appropriate sender key actions.

This convenience method applies the sender-key lifecycle for membership
changes:
- Member removed: Rotate sender key (forward secrecy)
- Member added: No rotation needed (just distribute current key)
- Metadata changed: Rotate recommended

#### Parameters

##### groupId

`string`

Group identifier

##### change

`"member_added"` \| `"member_removed"` \| `"metadata_changed"`

Type of membership change

#### Returns

`Promise`\<\{ `distributionMessage?`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `rotated`: `boolean`; \}\>

Distribution message if rotation occurred, for sending to members

#### Example

```typescript
// When a member is removed
const result = await signal.handleGroupMembershipChange(
  'group-123',
  'member_removed'
);

if (result.rotated) {
  // Distribute new key to remaining members
  for (const member of remainingMembers) {
    const encrypted = await signal.encryptMessage(
      member.address,
      JSON.stringify(result.distributionMessage)
    );
    await sendToMember(member, encrypted);
  }
}
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`handleGroupMembershipChange`](../interfaces/SignalProtocolClient.md#handlegroupmembershipchange)

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

True if sender key exists for this device

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`hasGroupSenderKey`](../interfaces/SignalProtocolClient.md#hasgroupsenderkey)

***

### hasSession()

> **hasSession**(`remoteAddress`): `Promise`\<`boolean`\>

Check if a session exists

#### Parameters

##### remoteAddress

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

Remote device's protocol address

#### Returns

`Promise`\<`boolean`\>

True if session exists

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`hasSession`](../interfaces/SignalProtocolClient.md#hassession)

***

### isInitialized()

> **isInitialized**(): `Promise`\<`boolean`\>

Check whether the client completed initialization

#### Returns

`Promise`\<`boolean`\>

True if identity keys exist and client is ready to use

***

### joinGroupViaInviteLink()

> **joinGroupViaInviteLink**(`url`, `userAci`, `userProfileKey`): `Promise`\<\{ `groupId`: [`GroupId`](../type-aliases/GroupId.md); `status`: `"joined"` \| `"pending_approval"`; \}\>

Join a group via invite link.

#### Parameters

##### url

`string`

##### userAci

`Uint8Array`

##### userProfileKey

`Uint8Array`

#### Returns

`Promise`\<\{ `groupId`: [`GroupId`](../type-aliases/GroupId.md); `status`: `"joined"` \| `"pending_approval"`; \}\>

***

### leaveGroup()

> **leaveGroup**(`groupId`, `userAci`): `Promise`\<`void`\>

Leave a group.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### userAci

`Uint8Array`

#### Returns

`Promise`\<`void`\>

***

### markAsRead()

> **markAsRead**(`messageId`): `Promise`\<`void`\>

Mark a message as read/delivered

Signals to the server that the message was successfully received
and processed. Server may delete the message based on privacy settings.

#### Parameters

##### messageId

`string`

The message ID from SendResult

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
// After processing received message
await signal.markAsRead(envelope.id);
```

***

### processGroupSenderKeyDistribution()

> **processGroupSenderKeyDistribution**(`groupId`, `senderId`, `senderDeviceId`, `message`): `Promise`\<`void`\>

Process a sender key distribution message from another group member

Call this when receiving a sender key distribution message from a group member.
After processing, you can decrypt messages from that member.

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

[`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md)

Distribution message containing the sender key

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
// Receive and process distribution message
const distributionMessage = JSON.parse(decryptedContent);
await signal.processGroupSenderKeyDistribution(
  'group-123',
  senderId,
  senderDeviceId,
  distributionMessage
);
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`processGroupSenderKeyDistribution`](../interfaces/SignalProtocolClient.md#processgroupsenderkeydistribution)

***

### processIncomingEnvelope()

> **processIncomingEnvelope**(`envelope`, `options?`): `Promise`\<`string`\>

Process an incoming encrypted message envelope.

Unified entry point for both foreground (relay) and background (HTTP) message processing.
Handles decryption and automatically sends SESAME retry requests on retryable failures.

This method:
1. Decodes base64 ciphertext from the envelope
2. Decrypts message using Double Ratchet
3. On retryable error: sends retry request via relay or options callback
4. Re-throws error for caller to handle

#### Parameters

##### envelope

[`IncomingEnvelope`](../interfaces/IncomingEnvelope.md)

The encrypted message envelope

##### options?

[`ProcessEnvelopeOptions`](../interfaces/ProcessEnvelopeOptions.md)

Transport callbacks for background (no relay) scenarios

#### Returns

`Promise`\<`string`\>

Decrypted plaintext

#### Throws

EncryptionError after sending retry request if decryption fails

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`processIncomingEnvelope`](../interfaces/SignalProtocolClient.md#processincomingenvelope)

***

### processIncomingEnvelopes()

> **processIncomingEnvelopes**(`envelopes`, `options?`): `Promise`\<(\{ `envelope`: [`IncomingEnvelope`](../interfaces/IncomingEnvelope.md); `plaintext`: `string`; \} \| \{ `envelope`: [`IncomingEnvelope`](../interfaces/IncomingEnvelope.md); `error`: `Error`; \})[]\>

Process multiple incoming encrypted message envelopes.

This is the preferred method for batch message processing. It handles:
1. Sorting PreKeyMessages before ciphertexts (SESAME session convergence)
2. Processing each envelope in order
3. Collecting results/errors for caller to handle

The sorting processes PreKeyMessages (which establish sessions)
before ciphertexts that depend on those sessions. SESAME Section 3.4
session convergence requires this when the client promotes archived sessions.

#### Parameters

##### envelopes

[`IncomingEnvelope`](../interfaces/IncomingEnvelope.md)[]

Array of encrypted message envelopes

##### options?

[`ProcessEnvelopeOptions`](../interfaces/ProcessEnvelopeOptions.md)

Transport callbacks for background scenarios

#### Returns

`Promise`\<(\{ `envelope`: [`IncomingEnvelope`](../interfaces/IncomingEnvelope.md); `plaintext`: `string`; \} \| \{ `envelope`: [`IncomingEnvelope`](../interfaces/IncomingEnvelope.md); `error`: `Error`; \})[]\>

Array of results, each either success (plaintext) or failure (error)

#### Example

```typescript
const results = await signal.processIncomingEnvelopes(pendingMessages);
for (const result of results) {
  if ('plaintext' in result) {
    handleDecryptedMessage(result.envelope, result.plaintext);
  } else {
    handleDecryptionError(result.envelope, result.error);
  }
}
```

#### See

https://signal.org/docs/specifications/sesame/ Section 3.4

***

### receive()

> **receive**(`message`): `Promise`\<`string`\>

Receive and decrypt message from another device (multi-device support)

Implements session convergence per SESAME spec.

#### Parameters

##### message

[`SesameMessage`](../interfaces/SesameMessage.md)

The encrypted Sesame message envelope

#### Returns

`Promise`\<`string`\>

Decrypted plaintext

***

### receiveIncomingEnvelopes()

> **receiveIncomingEnvelopes**(`envelopes`): `Promise`\<\{ `failedMessageIds`: `string`[]; `processedMessageIds`: `string`[]; \}\>

Receive a pulled batch through the subscription content handler.
The application must register onMessageDecrypted before calling this method.
Successful IDs are ready for transport acknowledgment.

#### Parameters

##### envelopes

[`IncomingEnvelope`](../interfaces/IncomingEnvelope.md)[]

#### Returns

`Promise`\<\{ `failedMessageIds`: `string`[]; `processedMessageIds`: `string`[]; \}\>

***

### registerHook()

> **registerHook**\<`K`\>(`name`, `callback`): `void`

Register a hook callback after construction

Enables dependency injection patterns where callers register hooks
after the DefaultSignalProtocolClient exists. ServicesProvider uses this
to wire up ContentManager's decryption hook.

#### Type Parameters

##### K

`K` *extends* keyof [`SignalProtocolClientHooks`](../interfaces/SignalProtocolClientHooks.md)

#### Parameters

##### name

`K`

The hook name to register

##### callback

`NonNullable`\<[`SignalProtocolClientHooks`](../interfaces/SignalProtocolClientHooks.md)\[`K`\]\>

The callback function to invoke

#### Returns

`void`

#### Example

```typescript
// In ServicesProvider: wire up ContentManager after creation
const signal = await DefaultSignalProtocolClient.create(userId, { storage, relay });
const content = new ContentManager({ db, signal });

signal.registerHook('onMessageDecrypted', content.getDecryptionHook());
signal.startRelaySubscription(); // Now safe to start
```

#### See

SignalProtocolClient.registerHook

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`registerHook`](../interfaces/SignalProtocolClient.md#registerhook)

***

### removeGroupMember()

> **removeGroupMember**(`groupId`, `editorAci`, `targetAci`): `Promise`\<`void`\>

Remove a member from a group. Triggers sender key rotation.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

##### targetAci

`Uint8Array`

#### Returns

`Promise`\<`void`\>

***

### rotateAccountIdentity()

> **rotateAccountIdentity**(`expectedCurrentCommitment`, `identityType?`): `Promise`\<`void`\>

Explicitly rotate this account's relay identity using a caller-authenticated
compare-and-swap commitment, then publish fresh prekeys for that namespace.
Normal sync and linked-device provisioning never call this operation.

#### Parameters

##### expectedCurrentCommitment

`Uint8Array`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md) = `'aci'`

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`rotateAccountIdentity`](../interfaces/SignalProtocolClient.md#rotateaccountidentity)

***

### rotateEcSignedPreKey()

> **rotateEcSignedPreKey**(): `Promise`\<`boolean`\>

Rotate EC signed prekey

Rotates only once the current prekey is older than the configured refresh
interval ([KEY\_REFRESH\_INTERVAL\_MS\_DEFAULT](../variables/KEY_REFRESH_INTERVAL_MS_DEFAULT.md), 2 days by default). It
is therefore safe to call more often than that. Generates a new EC signed
prekey
and uploads it to the relay if configured.

#### Returns

`Promise`\<`boolean`\>

True if the client rotated the key, false if not needed yet

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`rotateEcSignedPreKey`](../interfaces/SignalProtocolClient.md#rotateecsignedprekey)

***

### rotateGroupSenderKey()

> **rotateGroupSenderKey**(`groupId`): `Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

Rotate sender key for a group (forward secrecy on membership changes).

## When to Call

Per Signal Protocol specification, rotate sender keys on **membership changes**:

| Event | Action |
|-------|--------|
| Member REMOVED | **ALL members** must rotate (forward secrecy) |
| Member ADDED | Distribute current key to new member (no rotation needed) |
| Group metadata changed | Rotate recommended |

**Important**: The reference implementation does NOT use periodic or message-count-based rotation.
Only rotate when membership changes to maintain forward secrecy.

## Why Rotate on Member Removal?

After the group removes a member, they still hold the old sender key and could decrypt
future messages if nothing rotates the key. ALL remaining members must generate
new sender keys to prevent the removed member from reading future messages.

#### Parameters

##### groupId

`string`

Group identifier

#### Returns

`Promise`\<\{ `distributionMessage`: [`SenderKeyDistributionMessage`](../interfaces/SenderKeyDistributionMessage.md); `senderKeyId`: `string`; \}\>

New distribution message to share with remaining members

#### Example

```typescript
// When removing a member from a group
async function onMemberRemoved(groupId: string, remainingMembers: Member[]) {
  // Rotate our sender key (forward secrecy)
  const { distributionMessage } = await signal.rotateGroupSenderKey(groupId);

  // Distribute new key to remaining members via pairwise encryption
  for (const member of remainingMembers) {
    const encrypted = await signal.encryptMessage(
      member.address,
      JSON.stringify(distributionMessage)
    );
    await sendToMember(member, encrypted);
  }
}

// When adding a member - no rotation needed, just distribute current key
async function onMemberAdded(groupId: string, newMember: Member) {
  const { distributionMessage } = await signal.createGroupSenderKey(groupId);
  // Or get existing: signal.getGroupSenderKeyDistribution(groupId)
  const encrypted = await signal.encryptMessage(
    newMember.address,
    JSON.stringify(distributionMessage)
  );
  await sendToMember(newMember, encrypted);
}
```

#### See

handleGroupMembershipChange - Helper method for common membership patterns

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`rotateGroupSenderKey`](../interfaces/SignalProtocolClient.md#rotategroupsenderkey)

***

### rotateKyberPreKey()

> **rotateKyberPreKey**(): `Promise`\<`boolean`\>

Rotate the post-quantum KEM last-resort prekey.

Shares the signed prekey's refresh interval
([KEY\_REFRESH\_INTERVAL\_MS\_DEFAULT](../variables/KEY_REFRESH_INTERVAL_MS_DEFAULT.md), 2 days by default) and rotates
only after that interval elapses. Generates fresh ML-KEM/Kyber-compatible
key material and uploads it to the relay if configured.

#### Returns

`Promise`\<`boolean`\>

True if the client rotated the key, false if not needed yet

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`rotateKyberPreKey`](../interfaces/SignalProtocolClient.md#rotatekyberprekey)

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

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`runPeriodicCleanup`](../interfaces/SignalProtocolClient.md#runperiodiccleanup)

***

### send()

> **send**(`recipientId`, `content`, `options?`): `Promise`\<[`SendResult`](../interfaces/SendResult.md)\>

Send encrypted content to a user or group

This is the ONE way to send content. Handles:
- DataMessageInput: Structured proto content (serialized to protobuf)
- String content: Text or structured data (encoded to UTF-8 bytes)
- Uint8Array: Pre-serialized binary content (passed through)
- User recipients: Encrypts for all user's devices via SESAME
- Group recipients: Uses Sender Keys for O(1) encryption

The client normalizes all inputs to Uint8Array before they reach the cipher layer.

#### Parameters

##### recipientId

`string`

User ID or group ID (groups use the package group ID prefix)

##### content

`string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`DataMessageInput`](../interfaces/DataMessageInput.md)

DataMessageInput, string, or Uint8Array to encrypt and send

##### options?

[`SendOptions`](../interfaces/SendOptions.md)

Optional send options (isBinary for blob encryption, etc.)

#### Returns

`Promise`\<[`SendResult`](../interfaces/SendResult.md)\>

SendResult with messageId, timestamp, and device count

#### Example

```typescript
import { createGroupId } from '@open-e2ee/signal-protocol-sdk';

// Send text message
await signal.send('bob', 'Hello!');

// Send structured data
await signal.send('bob', { body: 'Hello!', timestamp: Date.now() });

// Send binary attachment (two-layer encryption)
await signal.send('bob', photoBytes, { isBinary: true, mimeType: 'image/jpeg' });

// Send to group (use createGroupId helper)
await signal.send(createGroupId('abc123'), 'Hello everyone!');
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`send`](../interfaces/SignalProtocolClient.md#send)

***

### sendReadReceipt()

> **sendReadReceipt**(`recipientUserId`, `timestamps`): `Promise`\<`void`\>

Send read receipt to original message sender (all devices)

Called when the user views messages in a conversation.
Similar to delivery receipts but indicates message was actually read.

Respects SDK privacy settings: if the configuration disables read receipts,
this method returns early without sending.

#### Parameters

##### recipientUserId

`string`

Original sender's user ID

##### timestamps

`number`[]

Server timestamps of the messages the user read

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`sendReadReceipt`](../interfaces/SignalProtocolClient.md#sendreadreceipt)

***

### sendTypingIndicator()

> **sendTypingIndicator**(`recipientUserId`, `recipientDeviceId`, `conversationId`, `action`, `groupId?`): `Promise`\<`void`\>

Send typing indicator to conversation recipient

Delegates to MessageOps.sendTypingIndicator for implementation.

#### Parameters

##### recipientUserId

`string`

##### recipientDeviceId

`number`

##### conversationId

`string`

##### action

[`TypingAction`](../enumerations/TypingAction.md)

##### groupId?

`string`

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`sendTypingIndicator`](../interfaces/SignalProtocolClient.md#sendtypingindicator)

***

### sendViewedReceipt()

> **sendViewedReceipt**(`recipientUserId`, `timestamps`): `Promise`\<`void`\>

Send viewed receipt to original message sender (all devices).

Uses the same privacy gate as read receipts.

#### Parameters

##### recipientUserId

`string`

##### timestamps

`number`[]

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`sendViewedReceipt`](../interfaces/SignalProtocolClient.md#sendviewedreceipt)

***

### startRelaySubscription()

> **startRelaySubscription**(): `void`

Start relay subscription for automatic message decryption

When configured with both `relay` and `onMessageDecrypted` hook, DefaultSignalProtocolClient will:
1. Subscribe to incoming envelopes from the relay
2. Decrypt messages appropriately (pairwise vs group/sender key)
3. Call onMessageDecrypted hook with DecryptedEnvelope (for ContentManager storage)
4. Mark messages as delivered on the relay

This enables ContentManager to store decrypted content in an encrypted SQLite
database without any knowledge of cryptography.

Callers can run this manually after registering hooks via registerHook().
Called automatically by create() when relay + hook configured.

#### Returns

`void`

#### See

SignalProtocolClient.startRelaySubscription

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`startRelaySubscription`](../interfaces/SignalProtocolClient.md#startrelaysubscription)

***

### startRetryRequestSubscription()

> **startRetryRequestSubscription**(): `void`

Start listening for retry requests from recipients (SESAME spec §6.2)

When a recipient cannot decrypt a message, they send a retry request.
This method subscribes to incoming retry requests and processes them
by resending the original message with a new session.

Automatically started if relay.subscribeRetryRequests is available.
Call this manually if you need to restart the subscription.

#### Returns

`void`

***

### stop()

> **stop**(): `Promise`\<`void`\>

Stop the Signal Protocol client and clean up resources

Call this when the user logs out or the app shuts down.
Unsubscribes from relay server and cleans up any pending operations.

#### Returns

`Promise`\<`void`\>

#### Example

```typescript
// On logout
await signal.stop();
```

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`stop`](../interfaces/SignalProtocolClient.md#stop)

***

### stopRelaySubscription()

> **stopRelaySubscription**(): `void`

Stop the relay subscription

Pauses message processing via the relay subscription without destroying
DefaultSignalProtocolClient state. startRelaySubscription() restarts the subscription.

Use this when the app backgrounds to let the background task handle messages.
Resume when the app foregrounds for real-time message delivery.

#### Returns

`void`

#### See

SignalProtocolClient.stopRelaySubscription

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`stopRelaySubscription`](../interfaces/SignalProtocolClient.md#stoprelaysubscription)

***

### syncBlockedRecipientsToLinkedDevices()

> **syncBlockedRecipientsToLinkedDevices**(`blocked`): `Promise`\<`void`\>

Sync the current blocked-recipient snapshot to the account's other linked devices.

The payload is a full snapshot, not a block/unblock delta.

#### Parameters

##### blocked

[`BlockedRecipientsSyncInput`](../interfaces/BlockedRecipientsSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncBlockedRecipientsToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncblockedrecipientstolinkeddevices)

***

### syncConfigurationToLinkedDevices()

> **syncConfigurationToLinkedDevices**(`configuration`): `Promise`\<`void`\>

Sync local account-level communication/privacy configuration to our other linked devices.

#### Parameters

##### configuration

[`ConfigurationSyncInput`](../interfaces/ConfigurationSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncConfigurationToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncconfigurationtolinkeddevices)

***

### syncGroup()

> **syncGroup**(`groupId`): `Promise`\<[`DecryptedGroup`](../interfaces/DecryptedGroup.md)\>

Sync group state from server.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

#### Returns

`Promise`\<[`DecryptedGroup`](../interfaces/DecryptedGroup.md)\>

***

### syncMediaAttachmentDeleteToLinkedDevices()

> **syncMediaAttachmentDeleteToLinkedDevices**(`entry`): `Promise`\<`void`\>

Sync a local media attachment delete event to our other linked devices.

#### Parameters

##### entry

[`MediaAttachmentDeleteSyncInput`](../interfaces/MediaAttachmentDeleteSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncMediaAttachmentDeleteToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncmediaattachmentdeletetolinkeddevices)

***

### syncReadToLinkedDevices()

> **syncReadToLinkedDevices**(`entries`): `Promise`\<`void`\>

Sync local read state to our other linked devices.

Unlike read receipts, this is account-local multi-device state and should
happen regardless of the user's remote read-receipt privacy preference.

#### Parameters

##### entries

[`ReadSyncEntryInput`](../interfaces/ReadSyncEntryInput.md)[]

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncReadToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncreadtolinkeddevices)

***

### syncRecipientUsernameToLinkedDevices()

> **syncRecipientUsernameToLinkedDevices**(`recipientUsername`): `Promise`\<`void`\>

Sync learned recipient username metadata to the account's other linked devices.

Remote usernames are transient metadata, but once one local device learns
them they should converge across the account's linked devices.

#### Parameters

##### recipientUsername

[`RecipientUsernameSyncInput`](../interfaces/RecipientUsernameSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncRecipientUsernameToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncrecipientusernametolinkeddevices)

***

### syncTaskNotificationAckToLinkedDevices()

> **syncTaskNotificationAckToLinkedDevices**(`input`): `Promise`\<`void`\>

Sync task-notification acknowledgment state to our other linked devices.

This is account-local notification state: if one device dismisses or acts
on a task reminder, the user's other devices should cancel their copies.

#### Parameters

##### input

`Omit`\<[`TaskNotificationAckSyncInput`](../interfaces/TaskNotificationAckSyncInput.md), `"acknowledgedOnDevice"`\>

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncTaskNotificationAckToLinkedDevices`](../interfaces/SignalProtocolClient.md#synctasknotificationacktolinkeddevices)

***

### syncToServer()

> **syncToServer**(`onProgress?`): `Promise`\<`void`\>

Sync the public prekey bundle to the configured relay.

create() calls this automatically when config names a relay.
Callers can also run it manually to retry after a failed initial sync.

Delegates to PreKeyOps.syncToServer for implementation.

#### Parameters

##### onProgress?

[`ProgressCallback`](../type-aliases/ProgressCallback.md)

#### Returns

`Promise`\<`void`\>

***

### syncUsernameStateToLinkedDevices()

> **syncUsernameStateToLinkedDevices**(`usernameState`): `Promise`\<`void`\>

Sync local username and username-link state to the account's other linked devices.

Linked devices converge on the same username-link handle and entropy
without rotating it.

#### Parameters

##### usernameState

[`UsernameStateSyncInput`](../interfaces/UsernameStateSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncUsernameStateToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncusernamestatetolinkeddevices)

***

### syncVerificationStateToLinkedDevices()

> **syncVerificationStateToLinkedDevices**(`verificationState`): `Promise`\<`void`\>

Sync local safety-number verification state to our other linked devices.

The client syncs only explicit `verified` and cleared-to-`default` states.
Key-conflict/untrusted state remains local and derived from identity-key
changes.

#### Parameters

##### verificationState

[`VerificationStateSyncInput`](../interfaces/VerificationStateSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncVerificationStateToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncverificationstatetolinkeddevices)

***

### syncViewOnceOpenToLinkedDevices()

> **syncViewOnceOpenToLinkedDevices**(`entry`): `Promise`\<`void`\>

Sync a local view-once open event to our other linked devices.

#### Parameters

##### entry

[`ViewOnceOpenSyncInput`](../interfaces/ViewOnceOpenSyncInput.md)

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`syncViewOnceOpenToLinkedDevices`](../interfaces/SignalProtocolClient.md#syncviewonceopentolinkeddevices)

***

### updateGroupAccessControl()

> **updateGroupAccessControl**(`groupId`, `editorAci`, `updates`): `Promise`\<`void`\>

Update a group's access control.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

##### updates

`Partial`\<`AccessControl`\>

#### Returns

`Promise`\<`void`\>

***

### updateGroupDescription()

> **updateGroupDescription**(`groupId`, `editorAci`, `description`): `Promise`\<`void`\>

Update a group's description.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

##### description

`string`

#### Returns

`Promise`\<`void`\>

***

### updateGroupTitle()

> **updateGroupTitle**(`groupId`, `editorAci`, `title`): `Promise`\<`void`\>

Update a group's title.

#### Parameters

##### groupId

[`GroupId`](../type-aliases/GroupId.md)

##### editorAci

`Uint8Array`

##### title

`string`

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

[`SendOptions`](../interfaces/SendOptions.md) & `object`

#### Returns

`Promise`\<[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md)\>

#### Implementation of

[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md).[`uploadAttachment`](../interfaces/SignalProtocolClient.md#uploadattachment)

***

### verify()

> **verify**(`userId`, `identityType?`): `Promise`\<[`SafetyNumber`](../interfaces/SafetyNumber.md)\>

Generate safety number for verifying identity with another user

Safety numbers allow users to verify they communicate with the
intended person and detect man-in-the-middle attacks.

#### Parameters

##### userId

`string`

The user ID to generate safety number for

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md) = `'aci'`

#### Returns

`Promise`\<[`SafetyNumber`](../interfaces/SafetyNumber.md)\>

SafetyNumber with numeric code and fingerprint for QR

#### Example

```typescript
const safetyNum = await signal.verify('bob');

// Show numeric code for phone/voice verification
console.log(`Safety Number: ${safetyNum.numeric}`);

// Generate QR code from fingerprint
const qrCode = generateQR(safetyNum.fingerprint);
```

***

### create()

> `static` **create**(`userId`, `config`): `Promise`\<`DefaultSignalProtocolClient`\>

Create and initialize a new DefaultSignalProtocolClient instance.

This low-level factory fully initializes the client before it returns
it. Most app code should prefer `createSignalProtocolClient()`, which
groups identity, adapters, and protocol policy in one object.

If config provides `relay`, the client automatically uploads the
public prekey bundle needed for end-to-end encrypted messaging.

#### Parameters

##### userId

`string`

User identifier for this device/client

##### config

[`SignalProtocolClientConfig`](../interfaces/SignalProtocolClientConfig.md)

Optional configuration for the client

#### Returns

`Promise`\<`DefaultSignalProtocolClient`\>

Fully initialized DefaultSignalProtocolClient instance

#### Example

```typescript
import { DefaultSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { inMemoryRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/memory';

// Local-only primary device.
const signal = await DefaultSignalProtocolClient.create('user-123', {
  storage,
});

// Linked device; storage must already contain provisioned identity material.
const signal = await DefaultSignalProtocolClient.create('user-123', {
  deviceId: 2,
  storage: provisionedLinkedDeviceStorage
});

// With relay sync.
const relay = inMemoryRelay();
const signal = await DefaultSignalProtocolClient.create('user-123', {
  storage,
  relay,
  onProgress: ({ stage, percent, message }) => {
    console.log(`${stage}: ${percent}% - ${message}`);
  }
});

// With full configuration
const signal = await DefaultSignalProtocolClient.create('user-123', {
  deviceId: 1,
  storage,
  relay,
  protocol: { postQuantum: 'required', braid: 'required' },
  onProgress,
  enableDebugLogging: true,
  ratchetConfig: { maxSkip: 2000 }
});

// For local development with in-memory adapters
const signal = await DefaultSignalProtocolClient.create('local-user', {
  protocolManager: inMemoryManager,
  storage: inMemoryStorage
});
```
