[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISignalProtocolRelayServer

# Interface: ISignalProtocolRelayServer

Server-side relay for encrypted envelope push delivery.

Responsibilities:
- Envelope delivery (push to devices via real-time subscription)
- Device registry (multi-device support, max 5 devices per user)
- Prekey management (X3DH/PQXDH key exchange)

Backed by the 16 tables the Convex component owns. `docs/SCHEMA.md` covers
what each stores and for how long.

## Example

```typescript
const relay: ISignalProtocolRelayServer = new ConvexSignalProtocolRelayServer(convex, signalApi, {
  currentUserId: userId,
});

// Subscribe to incoming envelopes
const unsubscribe = relay.subscribe(userId, deviceId, (envelope) => {
  // Decrypt and process
});

// Send encrypted envelope
await relay.send({
  targetUserId: 'bob',
  targetDeviceId: 1,
  senderUserId: 'alice',
  senderDeviceId: 1,
  ciphertext: encryptedBytes,
  messageType: 'ciphertext',
});
```

## Extends

- `IProvisioningService`.`IKeyRotationService`

## Properties

### groupServer?

> `readonly` `optional` **groupServer?**: [`IRelayGroupServer`](IRelayGroupServer.md)

Optional conforming Group System transport and issuance capability.

## Methods

### acknowledgeProvisioning()

> **acknowledgeProvisioning**(`sessionId`): `Promise`\<`void`\>

Acknowledge that the linked device finished persisting its local
bootstrap state, allowing the backend to clear the reversible
provisioning session state.

#### Parameters

##### sessionId

`string`

Session ID to finalize

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IProvisioningService.acknowledgeProvisioning`

***

### clearStaleKemPreKeys()

> **clearStaleKemPreKeys**(`userId`, `deviceId`, `identityType?`): `Promise`\<\{ `cleared`: `number`; \}\>

Clear stale KEM one-time prekeys during recovery.

Called when PREKEY_NOT_FOUND indicates Bob has stale one-time KEM keys
on the server that he no longer has private keys for. Clearing them lets
subsequent bundle fetches select a current one-time or last-resort key.

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<\{ `cleared`: `number`; \}\>

Number of keys cleared

***

### completeProvisioning()

> **completeProvisioning**(`sessionId`, `deviceMetadata`): `Promise`\<\{ `deviceId`: `number`; \}\>

Mark provisioning as complete and finalize linked-device registration.

#### Parameters

##### sessionId

`string`

Session ID to complete

##### deviceMetadata

Final device metadata, including the encrypted device name

###### appVersion?

`string`

###### encryptedDeviceName

`ArrayBuffer`

###### osVersion?

`string`

###### platform?

`string`

#### Returns

`Promise`\<\{ `deviceId`: `number`; \}\>

#### Inherited from

`IProvisioningService.completeProvisioning`

***

### connectNewDevice()

> **connectNewDevice**(`sessionId`, `ephemeralPublicKey`, `deviceMetadata`): `Promise`\<`void`\>

Connect a new device to an existing provisioning session.

#### Parameters

##### sessionId

`string`

Provisioning session ID from QR code

##### ephemeralPublicKey

`string`

New device's ECDH public key (Base64)

##### deviceMetadata

Non-sensitive device information available before provisioning completes

###### appVersion?

`string`

###### osVersion?

`string`

###### platform?

`string`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IProvisioningService.connectNewDevice`

***

### createGroupState()

> **createGroupState**(`groupId`, `encryptedState`, `authorization`): `Promise`\<`void`\>

Create a new encrypted group on the server.
Server stores and evaluates ciphertext structure but never decrypts it.

#### Parameters

##### groupId

`Uint8Array`

32-byte group identifier

##### encryptedState

`Uint8Array`

Serialized EncryptedGroup (opaque to server)

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

ZK auth credential for anonymous group access

#### Returns

`Promise`\<`void`\>

***

### createProvisioningSession()

> **createProvisioningSession**(`userId`, `ephemeralPublicKey`): `Promise`\<\{ `sessionId`: `string`; \}\>

Create a new provisioning session.

#### Parameters

##### userId

`string`

User ID creating the session

##### ephemeralPublicKey

`string`

Base64-encoded ECDH public key for key agreement

#### Returns

`Promise`\<\{ `sessionId`: `string`; \}\>

Session ID for the provisioning flow

#### Inherited from

`IProvisioningService.createProvisioningSession`

***

### deleteProvisioningSession()

> **deleteProvisioningSession**(`sessionId`, `userId?`): `Promise`\<`void`\>

Delete/cancel a provisioning session.

#### Parameters

##### sessionId

`string`

Session ID to delete

##### userId?

`string`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IProvisioningService.deleteProvisioningSession`

***

### fetchPreKeyBundle()

> **fetchPreKeyBundle**(`userId`, `deviceId`, `fetcherUserId?`, `identityType?`): `Promise`\<[`RelayPreKeyBundle`](RelayPreKeyBundle.md) \| `null`\>

Fetch prekey bundle for session establishment.

Atomically consumes one EC and one KEM one-time prekey.
Returns bundle with identity key, signed prekey, and optional one-time keys.

#### Parameters

##### userId

`string`

Target user ID

##### deviceId

`number`

Target device ID

##### fetcherUserId?

`string`

Deprecated, ignored. The server derives fetcher identity from auth.

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`RelayPreKeyBundle`](RelayPreKeyBundle.md) \| `null`\>

Prekey bundle or null if device not found

***

### fetchSenderCertificate()?

> `optional` **fetchSenderCertificate**(`deviceId`): `Promise`\<`string`\>

Fetch a sender certificate for sealed sender messaging.

The certificate binds the user's uuid, deviceId, and identity key,
signed by the server's trust root key. Expires after 24 hours.

#### Parameters

##### deviceId

`number`

Device ID (1-5) to bind the certificate to

#### Returns

`Promise`\<`string`\>

Base64-encoded serialized SenderCertificate

***

### getActiveDevices()

> **getActiveDevices**(`userId`): `Promise`\<[`GroupMemberDevice`](GroupMemberDevice.md)[]\>

Get all active devices for a user.
Used for local-first member resolution (caller provides user IDs,
relay resolves to device IDs).

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<[`GroupMemberDevice`](GroupMemberDevice.md)[]\>

***

### getDevices()

> **getDevices**(`userId`): `Promise`\<[`DeviceInfo`](DeviceInfo.md)[]\>

Get all active devices for a user.
Used for multi-device fanout during encryption.

#### Parameters

##### userId

`string`

Target user ID

#### Returns

`Promise`\<[`DeviceInfo`](DeviceInfo.md)[]\>

Array of device info (max 5 devices)

***

### getEcSignedPreKeyMetadata()

> **getEcSignedPreKeyMetadata**(`userId`, `deviceId`, `identityType?`): `Promise`\<\{ `createdAt`: `number`; `expiresAt`: `number`; `keyId`: `number`; `publicKey`: `string`; \} \| `null`\>

Get EC signed prekey metadata for rotation checks and server key verification.

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<\{ `createdAt`: `number`; `expiresAt`: `number`; `keyId`: `number`; `publicKey`: `string`; \} \| `null`\>

Metadata with timestamps and publicKey, or null if no key exists

#### Inherited from

`IKeyRotationService.getEcSignedPreKeyMetadata`

***

### getGroupChanges()

> **getGroupChanges**(`groupId`, `fromVersion`, `authorization`): `Promise`\<`GroupChangePage`\>

Get one page of group change log entries after a given version.
Used for incremental state synchronization.

Authorization runs at the `fromVersion` snapshot, and the
requester must be a member there. Serve through the first transition
that makes the requester unreadable, inclusive, and do not serve later
transitions under that request. A page cut for size sets `hasMore`.
The client resumes from the last served version.

#### Parameters

##### groupId

`Uint8Array`

32-byte group identifier

##### fromVersion

`number`

Fetch changes with version > fromVersion

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

ZK auth credential for anonymous group access

#### Returns

`Promise`\<`GroupChangePage`\>

One authorized contiguous change-log page in version order

***

### getGroupJoinInfo()

> **getGroupJoinInfo**(`groupId`, `inviteLinkPassword`, `authorization`): `Promise`\<\{ `encryptedJoinInfo`: `Uint8Array`; `version`: `number`; \} \| `null`\>

Get the reduced invite-link projection after independent password
verification. This response never includes member lists.

#### Parameters

##### groupId

`Uint8Array`

##### inviteLinkPassword

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<\{ `encryptedJoinInfo`: `Uint8Array`; `version`: `number`; \} \| `null`\>

***

### getGroupState()

> **getGroupState**(`groupId`, `authorization`, `version?`): `Promise`\<\{ `baselineSignature`: `Uint8Array`; `encryptedState`: `Uint8Array`; `version`: `number`; \} \| `null`\>

Get encrypted group state.

#### Parameters

##### groupId

`Uint8Array`

32-byte group identifier

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

ZK auth credential for anonymous group access

##### version?

`number`

Optional exact historical version for a race-safe baseline

#### Returns

`Promise`\<\{ `baselineSignature`: `Uint8Array`; `encryptedState`: `Uint8Array`; `version`: `number`; \} \| `null`\>

Encrypted state + version, or null if the group/version is not found

***

### getIdentityKey()

> **getIdentityKey**(`userId`, `identityType?`): `Promise`\<[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md) \| `null`\>

Get the account-level canonical composite identity.

#### Parameters

##### userId

`string`

Target user ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md) \| `null`\>

Composite identity or null if not found

***

### getKemLastResortPreKeyMetadata()

> **getKemLastResortPreKeyMetadata**(`userId`, `deviceId`, `identityType?`): `Promise`\<\{ `createdAt`: `number`; `expiresAt`: `number`; `keyId`: `number`; `publicKey`: `string`; \} \| `null`\>

Get KEM last-resort prekey metadata for rotation checks and server key verification.

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<\{ `createdAt`: `number`; `expiresAt`: `number`; `keyId`: `number`; `publicKey`: `string`; \} \| `null`\>

Metadata with timestamps, publicKey, and keyId, or null if no key exists

#### Inherited from

`IKeyRotationService.getKemLastResortPreKeyMetadata`

***

### getPreKeyCount()

> **getPreKeyCount**(`userId`, `deviceId`, `type`, `identityType?`): `Promise`\<`number`\>

Get count of remaining one-time prekeys.
Client should upload more when count < 10.

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device ID

##### type

`"ec"` \| `"kem"`

'ec' for X25519, 'kem' for ML-KEM-1024

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

***

### getProvisioningMessage()

> **getProvisioningMessage**(`sessionId`): `Promise`\<\{ `expiresAt`: `number` \| `null`; `message`: `string` \| `null`; `status`: `"completed"` \| `"waiting"` \| `"connected"` \| `"ready"` \| `"linked_pending_ack"` \| `"rolled_back"` \| `"expired"`; \}\>

Get provisioning message for new device.

#### Parameters

##### sessionId

`string`

Provisioning session ID

#### Returns

`Promise`\<\{ `expiresAt`: `number` \| `null`; `message`: `string` \| `null`; `status`: `"completed"` \| `"waiting"` \| `"connected"` \| `"ready"` \| `"linked_pending_ack"` \| `"rolled_back"` \| `"expired"`; \}\>

Status and encrypted message (if ready)

#### Inherited from

`IProvisioningService.getProvisioningMessage`

***

### heartbeat()

> **heartbeat**(`deviceId`): `Promise`\<`void`\>

Lightweight heartbeat. Writes only to heartbeat table, triggers 0 query reruns

#### Parameters

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

***

### issueAuthCredential()

> **issueAuthCredential**(`userId`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Issue a blinded auth credential for anonymous group access.

#### Parameters

##### userId

`string`

User requesting the credential

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Blinded auth credential bytes

***

### markDelivered()

> **markDelivered**(`envelopeId`): `Promise`\<`void`\>

Mark envelope as delivered.
Depending on privacy settings, may delete immediately or mark for cleanup.

#### Parameters

##### envelopeId

`string`

ID from send() or subscription

#### Returns

`Promise`\<`void`\>

***

### markDeviceConnected()

> **markDeviceConnected**(`deviceId`): `Promise`\<`void`\>

Mark device as connected (online).
Called when WebSocket connects.
The server derives userId from the JWT.

#### Parameters

##### deviceId

`number`

Device ID (1-5)

#### Returns

`Promise`\<`void`\>

***

### markDeviceDisconnected()

> **markDeviceDisconnected**(`deviceId`): `Promise`\<`void`\>

Mark device as disconnected (offline).
Called when WebSocket disconnects gracefully.
The server derives userId from the JWT.

#### Parameters

##### deviceId

`number`

Device ID (1-5)

#### Returns

`Promise`\<`void`\>

***

### provisionIdentityKey()

> **provisionIdentityKey**(`request`): `Promise`\<`void`\>

Provision a device against the account-level canonical composite identity.
Creates an absent identity, accepts an exact tuple match for linked
devices, and rejects a different tuple without mutating device metadata.

#### Parameters

##### request

[`AccountIdentityProvisioning`](AccountIdentityProvisioning.md)

#### Returns

`Promise`\<`void`\>

***

### refreshGroupSendEndorsements()?

> `optional` **refreshGroupSendEndorsements**(`groupId`, `authorization`): `Promise`\<\{ `endorsements`: `Uint8Array`; `expiration`: `number`; \}\>

Refresh group send endorsements from the server.
Returns serialized endorsement response and expiration.

#### Parameters

##### groupId

`Uint8Array`

32-byte group identifier

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

ZK auth presentation + group public params

#### Returns

`Promise`\<\{ `endorsements`: `Uint8Array`; `expiration`: `number`; \}\>

Endorsement response bytes and expiration epoch seconds

***

### registerDevice()

> **registerDevice**(`userId`, `device`): `Promise`\<`number`\>

Register this device with the server.

For first device: deviceId = 1 (PRIMARY_ID)
For linked devices: server assigns 2-5

#### Parameters

##### userId

`string`

Current user ID

##### device

[`DeviceRegistration`](DeviceRegistration.md)

Device registration info

#### Returns

`Promise`\<`number`\>

Assigned device ID

***

### removeDevice()

> **removeDevice**(`userId`, `deviceId`): `Promise`\<`void`\>

Remove a device from the registry.
Also deletes all prekeys and pending envelopes for that device.

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device to remove

#### Returns

`Promise`\<`void`\>

***

### rollbackProvisioning()

> **rollbackProvisioning**(`sessionId`): `Promise`\<`void`\>

Undo a completed provisioning link if the new device fails to persist its
local bootstrap state after the server-side link succeeded.

#### Parameters

##### sessionId

`string`

Session ID to roll back

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IProvisioningService.rollbackProvisioning`

***

### rotateIdentityKey()

> **rotateIdentityKey**(`request`): `Promise`\<`void`\>

Rotate an existing account-level composite identity using compare-and-swap.
A successful rotation invalidates prekeys for every linked device in the
selected identity namespace.

#### Parameters

##### request

[`AccountIdentityRotation`](AccountIdentityRotation.md)

#### Returns

`Promise`\<`void`\>

***

### send()

> **send**(`envelope`): `Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; \}\>

Send encrypted envelope to a device.
Server pushes to recipient via their subscription.

#### Parameters

##### envelope

[`Envelope`](Envelope.md)

Encrypted envelope with targeting info

#### Returns

`Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; \}\>

Message ID and server timestamp (for delivery receipt matching)

***

### sendMultiRecipientUnidentified()?

> `optional` **sendMultiRecipientUnidentified**(`sentMessageBase64`, `auth`, `timestamp`, `recipientUserIds?`, `clientMessageId?`): `Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; `uuids404`: `string`[]; \}\>

Send a V2 multi-recipient sealed sender message.

Client sends the full V2 binary blob (base64-encoded).
Relay parses client-side, sends structured JSON to mutation.
Server constructs per-device ReceivedMessage blobs and fans out.

#### Parameters

##### sentMessageBase64

`string`

Base64-encoded V2 multi-recipient binary blob

##### auth

[`SealedSenderAuth`](../type-aliases/SealedSenderAuth.md)

Sealed sender authentication (access key or group send token)

##### timestamp

`number`

Client timestamp for message identification

##### recipientUserIds?

`string`[]

Original user IDs in same order as binary recipients

##### clientMessageId?

`string`

#### Returns

`Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; `uuids404`: `string`[]; \}\>

Message ID, server timestamp, and list of unknown recipient UUIDs

***

### sendProvisioningMessage()

> **sendProvisioningMessage**(`sessionId`, `encryptedMessage`, `userId?`): `Promise`\<`void`\>

Send encrypted provisioning message from primary to new device.

#### Parameters

##### sessionId

`string`

Provisioning session ID

##### encryptedMessage

`string`

AES-GCM encrypted payload (JSON string with ciphertext, iv, authTag)

##### userId?

`string`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IProvisioningService.sendProvisioningMessage`

***

### sendRetryRequest()?

> `optional` **sendRetryRequest**(`request`): `Promise`\<`void`\>

Send retry request to the original sender.

The recipient calls this when decryption fails. The retry request stays
unencrypted (per SESAME spec) and contains only the message ID
and reason. Transport is TLS-secured.

#### Parameters

##### request

[`RetryRequest`](RetryRequest.md)

Retry request with sender/requester info and failed sequence number

#### Returns

`Promise`\<`void`\>

***

### sendUnidentified()?

> `optional` **sendUnidentified**(`envelope`, `auth`): `Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; \}\>

Send a sealed sender message (anonymous delivery).

The server does NOT know the sender. The ciphertext is an
UnidentifiedSenderMessage that the recipient unseals to discover
the sender's identity via the embedded certificate.

#### Parameters

##### envelope

[`Envelope`](Envelope.md)

Sealed sender envelope (senderUserId/senderDeviceId are empty strings/0)

##### auth

[`SealedSenderAuth`](../type-aliases/SealedSenderAuth.md)

Authentication for anonymous delivery (access key or group send token)

#### Returns

`Promise`\<\{ `messageId`: `string`; `serverTimestamp`: `number`; \}\>

Message ID and server timestamp

***

### submitGroupChange()

> **submitGroupChange**(`groupId`, `expectedVersion`, `actions`, `inviteLinkPassword`, `authorization`): `Promise`\<[`GroupChangeEntry`](GroupChangeEntry.md)\>

Submit a group change with optimistic concurrency control.
Server validates expectedVersion === currentVersion before accepting.

#### Parameters

##### groupId

`Uint8Array`

32-byte group identifier

##### expectedVersion

`number`

Expected current version (for optimistic concurrency)

##### actions

`Uint8Array`

Client-proposed serialized Actions

##### inviteLinkPassword

`Uint8Array`

Required independently for link-join submissions

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

ZK auth credential for anonymous group access

#### Returns

`Promise`\<[`GroupChangeEntry`](GroupChangeEntry.md)\>

Exact accepted Actions bytes and their server signature

#### Throws

ConflictError if expectedVersion !== currentVersion

***

### subscribe()

> **subscribe**(`userId`, `deviceId`, `onEnvelope`, `options?`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Subscribe to incoming envelopes for this device.
Real-time push via Convex subscription / WebSocket.

#### Parameters

##### userId

`string`

Current user ID

##### deviceId

`number`

This device's ID (1-5)

##### onEnvelope

(`envelope`) => `void`

Callback for each incoming envelope

##### options?

Optional batching callbacks for notification coalescing

###### onBatchEnd?

() => `void`

Called when batch is complete (idle detected)

###### onBatchStart?

() => `void`

Called when first message in a batch arrives

#### Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)

Unsubscribe function

***

### subscribeRetryRequests()?

> `optional` **subscribeRetryRequests**(`userId`, `deviceId`, `handler`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Subscribe to incoming retry requests for this device.

Called by sender to listen for retry requests from recipients.
When a retry request arrives, the sender should:
1. Look up the MessageRecord by sequence number
2. Fetch the requester's current prekey bundle
3. Establish a new session (X3DH/PQXDH)
4. Re-encrypt and send the original message

#### Parameters

##### userId

`string`

Current user ID (the original sender)

##### deviceId

`number`

This device's ID

##### handler

(`request`) => `Promise`\<`void`\>

Callback for each incoming retry request

#### Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)

Unsubscribe function

***

### uploadEcSignedPreKey()

> **uploadEcSignedPreKey**(`userId`, `ecSignedPreKey`, `identityType?`): `Promise`\<`void`\>

Upload an EC signed prekey.
Convenience wrapper around uploadPreKeys for key rotation.

#### Parameters

##### userId

`string`

User ID

##### ecSignedPreKey

[`EcSignedPreKeyUpload`](EcSignedPreKeyUpload.md)

EC signed prekey to upload

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### uploadKemLastResortPreKey()

> **uploadKemLastResortPreKey**(`userId`, `kemLastResortPreKey`, `identityType?`): `Promise`\<`void`\>

Upload a KEM last-resort (post-quantum) prekey.
Convenience wrapper around uploadPreKeys for key rotation.

#### Parameters

##### userId

`string`

User ID

##### kemLastResortPreKey

[`KemLastResortPreKeyUpload`](KemLastResortPreKeyUpload.md)

KEM last-resort prekey to upload

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### uploadPreKeys()

> **uploadPreKeys**(`userId`, `deviceId`, `keys`, `identityType?`): `Promise`\<`void`\>

Upload prekeys for this device (batch upload).

Typically called:
- On registration: 100 EC + 1 signed + 100 KEM + 1 last-resort
- When count < 10: replenish one-time keys

#### Parameters

##### userId

`string`

User ID

##### deviceId

`number`

Device ID

##### keys

[`PreKeyUpload`](PreKeyUpload.md)[]

Array of prekeys to upload

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>
