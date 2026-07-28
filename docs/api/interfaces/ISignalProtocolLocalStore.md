[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISignalProtocolLocalStore

# Interface: ISignalProtocolLocalStore

Signal Protocol local store interface.

Canonical device/browser-local persistence for Signal Protocol state:
- identity keys and registrations
- sessions and sender keys
- SESAME multi-device state
- message records and local metadata

This is the interface that local store adapters should implement.

## Extends

- [`IProtocolStore`](IProtocolStore.md).[`ISesameStore`](ISesameStore.md).[`ISenderKeyStore`](ISenderKeyStore.md).`IMessageRecordStore`

## Methods

### acceptContactIdentityRotation()

> **acceptContactIdentityRotation**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Explicitly accept a changed tuple and atomically delete every session for
that user; the previous tuple becomes rollback history.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`acceptContactIdentityRotation`](IProtocolStore.md#acceptcontactidentityrotation)

***

### acceptContactIdentityRotationAndDeleteSessions()

> **acceptContactIdentityRotationAndDeleteSessions**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Atomically rotate one per-user identity tuple and delete every bound device session.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`acceptContactIdentityRotationAndDeleteSessions`](IProtocolStore.md#acceptcontactidentityrotationanddeletesessions)

***

### archiveCurrentSession()

> **archiveCurrentSession**(`address`, `newSession?`): `Promise`\<`void`\>

Archive the current session and optionally start a new one.

Used when:
- Identity key changes (possible MITM)
- Registration ID changes (app reinstall detected)
- Manual session reset

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

##### newSession?

[`SessionState`](SessionState.md) \| `null`

Optional new session to set as current

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`archiveCurrentSession`](IProtocolStore.md#archivecurrentsession)

***

### cleanupExpiredSessions()

> **cleanupExpiredSessions**(`maxRecv`): `Promise`\<`number`\>

Delete expired sessions (sessions older than MAXRECV threshold).

#### Parameters

##### maxRecv

`number`

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`cleanupExpiredSessions`](ISesameStore.md#cleanupexpiredsessions)

***

### clearAllKeys()

> **clearAllKeys**(): `Promise`\<`void`\>

Clear all encryption keys (use with caution!).

This should only be used for:
- Account deletion
- Reset after security incident
- Local development

#### Returns

`Promise`\<`void`\>

***

### clearAllMessageRecords()

> **clearAllMessageRecords**(): `Promise`\<`number`\>

Clear all message records (for device re-registration)

#### Returns

`Promise`\<`number`\>

#### Inherited from

`IMessageRecordStore.clearAllMessageRecords`

***

### clearAllSessions()

> **clearAllSessions**(): `Promise`\<`void`\>

Clear all sessions from storage.
Used during force key reset.

#### Returns

`Promise`\<`void`\>

***

### commitSessionTrust()

> **commitSessionTrust**(`commit`): `Promise`\<`void`\>

Atomically pin/match trust, store the session, and consume referenced one-time prekeys.

#### Parameters

##### commit

[`SessionTrustCommit`](SessionTrustCommit.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`commitSessionTrust`](IProtocolStore.md#commitsessiontrust)

***

### countSkippedSenderKeys()

> **countSkippedSenderKeys**(`groupId`, `senderId`, `senderDeviceId`): `Promise`\<`number`\>

Count skipped keys for a sender (for enforcing maxSkippedKeys limit).

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

`Promise`\<`number`\>

Number of stored skipped keys for this sender

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`countSkippedSenderKeys`](ISenderKeyStore.md#countskippedsenderkeys)

***

### deleteAllPreKeys()

> **deleteAllPreKeys**(`identityType?`): `Promise`\<\{ `ecOneTimePreKeys`: `number`; `ecSignedPreKeys`: `number`; `kemOneTimePreKeys`: `number`; `kyberPreKeys`: `number`; \}\>

Delete all prekeys from storage (preserves identity keys and sessions).
Used for recovery from identifier collision per PQXDH §4.13.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<\{ `ecOneTimePreKeys`: `number`; `ecSignedPreKeys`: `number`; `kemOneTimePreKeys`: `number`; `kyberPreKeys`: `number`; \}\>

Counts of deleted prekeys by type

***

### deleteAllSenderKeysForGroup()

> **deleteAllSenderKeysForGroup**(`groupId`): `Promise`\<`number`\>

Delete all sender keys for a group (when group is deleted).

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`deleteAllSenderKeysForGroup`](ISenderKeyStore.md#deleteallsenderkeysforgroup)

***

### deleteDeviceRecord()

> **deleteDeviceRecord**(`userId`, `deviceId`): `Promise`\<`void`\>

Delete device record.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`deleteDeviceRecord`](ISesameStore.md#deletedevicerecord)

***

### deleteExpiredMessageRecords()

> **deleteExpiredMessageRecords**(`maxAgeMs`): `Promise`\<`number`\>

Delete all expired message records older than maxAgeMs

#### Parameters

##### maxAgeMs

`number`

#### Returns

`Promise`\<`number`\>

#### Inherited from

`IMessageRecordStore.deleteExpiredMessageRecords`

***

### deleteMessageRecord()

> **deleteMessageRecord**(`sessionId`, `timestamp`): `Promise`\<`void`\>

Delete a message record by session and timestamp.

Called when processing delivery receipts to clean up confirmed messages.

#### Parameters

##### sessionId

`string`

##### timestamp

`number`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IMessageRecordStore.deleteMessageRecord`

***

### deleteMessageRecordsForSession()

> **deleteMessageRecordsForSession**(`sessionId`): `Promise`\<`number`\>

Delete all message records for a session

#### Parameters

##### sessionId

`string`

#### Returns

`Promise`\<`number`\>

#### Inherited from

`IMessageRecordStore.deleteMessageRecordsForSession`

***

### deleteOldestSkippedSenderKeys()

> **deleteOldestSkippedSenderKeys**(`groupId`, `senderId`, `senderDeviceId`, `count`): `Promise`\<`number`\>

Delete oldest skipped keys to make room for new ones.

Called when maxSkippedKeys limit is reached.

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

##### count

`number`

Number of oldest keys to delete

#### Returns

`Promise`\<`number`\>

Number of deleted keys

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`deleteOldestSkippedSenderKeys`](ISenderKeyStore.md#deleteoldestskippedsenderkeys)

***

### deleteSenderKey()

> **deleteSenderKey**(`groupId`, `userId`, `deviceId`): `Promise`\<`void`\>

Delete sender key for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`deleteSenderKey`](ISenderKeyStore.md#deletesenderkey)

***

### deleteSessionRecord()

> **deleteSessionRecord**(`address`): `Promise`\<`void`\>

Delete session record.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`deleteSessionRecord`](IProtocolStore.md#deletesessionrecord)

***

### deleteSkippedSenderKey()

> **deleteSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`): `Promise`\<`void`\>

Delete skipped message key after use.

Called after successfully decrypting an out-of-order message.

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

##### chainIndex

`number`

The message index to delete

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`deleteSkippedSenderKey`](ISenderKeyStore.md#deleteskippedsenderkey)

***

### deleteStaleRecords()

> **deleteStaleRecords**(`maxLatency`): `Promise`\<`number`\>

Delete stale device records (orphaned sessions older than MAXLATENCY).

#### Parameters

##### maxLatency

`number`

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`deleteStaleRecords`](ISesameStore.md#deletestalerecords)

***

### getAllEcSignedPreKeys()?

> `optional` **getAllEcSignedPreKeys**(`identityType?`): `Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md)[]\>

Get all stored EC signed prekeys (current + archived).

Used for cleanup and debugging.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md)[]\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getAllEcSignedPreKeys`](IProtocolStore.md#getallecsignedprekeys)

***

### getAllSenderKeysForGroup()

> **getAllSenderKeysForGroup**(`groupId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md)[]\>

Get all sender keys for a group (for admin operations).

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md)[]\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`getAllSenderKeysForGroup`](ISenderKeyStore.md#getallsenderkeysforgroup)

***

### getAllUserIds()

> **getAllUserIds**(): `Promise`\<`string`[]\>

Get all user IDs with SESAME records.

#### Returns

`Promise`\<`string`[]\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`getAllUserIds`](ISesameStore.md#getalluserids)

***

### getContactIdentity()

> **getContactIdentity**(`address`, `identityType?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md) \| `null`\>

Get a contact's saved identity key.

Returns null if no identity key has been saved for this address.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md) \| `null`\>

Contact's identity key or null

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getContactIdentity`](IProtocolStore.md#getcontactidentity)

***

### getDetailedStats()

> **getDetailedStats**(): `Promise`\<\{ `ecOneTimePreKeys`: `number`; `ecSignedPreKeys`: `number`; `kemOneTimePreKeys`: `number`; `kyberPreKeys`: `number`; `sessions`: `number`; `users`: `number`; \}\>

Get detailed statistics about stored data.

#### Returns

`Promise`\<\{ `ecOneTimePreKeys`: `number`; `ecSignedPreKeys`: `number`; `kemOneTimePreKeys`: `number`; `kyberPreKeys`: `number`; `sessions`: `number`; `users`: `number`; \}\>

***

### getDeviceRecord()

> **getDeviceRecord**(`userId`, `deviceId`): `Promise`\<[`DeviceRecord`](DeviceRecord.md) \| `null`\>

Get device record for a specific user's device.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`DeviceRecord`](DeviceRecord.md) \| `null`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`getDeviceRecord`](ISesameStore.md#getdevicerecord)

***

### getDeviceSession()

> **getDeviceSession**(`userId`, `deviceId`): `Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

Get the session for a device.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

The SessionRecord, or null if no session exists.

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`getDeviceSession`](ISesameStore.md#getdevicesession)

***

### getEcOneTimePreKeys()

> **getEcOneTimePreKeys**(`identityType?`): `Promise`\<[`EcOneTimePreKey`](EcOneTimePreKey.md)[]\>

Retrieve all EC one-time prekeys.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcOneTimePreKey`](EcOneTimePreKey.md)[]\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getEcOneTimePreKeys`](IProtocolStore.md#geteconetimeprekeys)

***

### getEcSignedPreKey()

> **getEcSignedPreKey**(`keyId?`, `identityType?`): `Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md) \| `null`\>

Retrieve EC signed prekey by ID.

#### Parameters

##### keyId?

`number`

Optional key ID to retrieve. If not provided, returns the current (most recent) EC signed prekey.

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md) \| `null`\>

The EC signed prekey, or null if not found

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getEcSignedPreKey`](IProtocolStore.md#getecsignedprekey)

***

### getEcSignedPreKeyMaxId()

> **getEcSignedPreKeyMaxId**(`identityType?`): `Promise`\<`number`\>

Get the maximum EC signed prekey ID in storage.
Used to generate new keyIds that won't collide with existing ones.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

The highest EC signed prekey ID, or 0 if none exist

***

### getIdentityKey()

> **getIdentityKey**(`identityType?`): `Promise`\<[`IdentityKeyPair`](IdentityKeyPair.md) \| `null`\>

Retrieve our identity key pair.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`IdentityKeyPair`](IdentityKeyPair.md) \| `null`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getIdentityKey`](IProtocolStore.md#getidentitykey)

***

### getKemOneTimePreKey()

> **getKemOneTimePreKey**(`keyId`, `identityType?`): `Promise`\<[`KemOneTimePreKey`](../namespaces/keys/interfaces/KemOneTimePreKey.md) \| `null`\>

Retrieve a specific one-time KEM prekey by ID.
Used during session establishment to find the key for decapsulation.

#### Parameters

##### keyId

`number`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`KemOneTimePreKey`](../namespaces/keys/interfaces/KemOneTimePreKey.md) \| `null`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getKemOneTimePreKey`](IProtocolStore.md#getkemonetimeprekey)

***

### getKemOneTimePreKeyCount()

> **getKemOneTimePreKeyCount**(`identityType?`): `Promise`\<`number`\>

Get count of available one-time KEM prekeys.
Used to determine when to replenish the prekey pool.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getKemOneTimePreKeyCount`](IProtocolStore.md#getkemonetimeprekeycount)

***

### getKemOneTimePreKeys()

> **getKemOneTimePreKeys**(`identityType?`): `Promise`\<[`KemOneTimePreKey`](../namespaces/keys/interfaces/KemOneTimePreKey.md)[]\>

Retrieve all one-time KEM prekeys.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`KemOneTimePreKey`](../namespaces/keys/interfaces/KemOneTimePreKey.md)[]\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getKemOneTimePreKeys`](IProtocolStore.md#getkemonetimeprekeys)

***

### getKyberPreKey()

> **getKyberPreKey**(`identityType?`): `Promise`\<[`KyberPreKey`](KyberPreKey.md) \| `null`\>

Retrieve Kyber prekey.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`KyberPreKey`](KyberPreKey.md) \| `null`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getKyberPreKey`](IProtocolStore.md#getkyberprekey)

***

### getKyberPreKeyMaxId()

> **getKyberPreKeyMaxId**(`identityType?`): `Promise`\<`number`\>

Get the maximum Kyber prekey ID in storage.
Used to generate new keyIds that won't collide with existing ones.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

The highest Kyber prekey ID, or 0 if none exist

***

### getLocalRegistrationId()

> **getLocalRegistrationId**(`identityType?`): `Promise`\<`number`\>

Get our local registration ID.

Registration ID is a random 16-bit integer generated once per install.
Used to detect session resets when app is reinstalled.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getLocalRegistrationId`](IProtocolStore.md#getlocalregistrationid)

***

### getMessageRecord()

> **getMessageRecord**(`sessionId`, `timestamp`): `Promise`\<[`MessageRecord`](MessageRecord.md) \| `null`\>

Get a message record by session and timestamp (PRIMARY lookup method).

Per Signal Protocol, messages are identified by client timestamp.

#### Parameters

##### sessionId

`string`

##### timestamp

`number`

#### Returns

`Promise`\<[`MessageRecord`](MessageRecord.md) \| `null`\>

#### Inherited from

`IMessageRecordStore.getMessageRecord`

***

### getMetadata()

> **getMetadata**(`key`): `Promise`\<`string` \| `null`\>

Get a metadata value by key.
Used for persisting operational timestamps (e.g., lastForcedPreKeyRotation).

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`string` \| `null`\>

***

### getSenderKey()

> **getSenderKey**(`groupId`, `userId`, `deviceId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md) \| `null`\>

Retrieve sender key state for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md) \| `null`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`getSenderKey`](ISenderKeyStore.md#getsenderkey)

***

### getSenderKeyRecord()

> **getSenderKeyRecord**(`groupId`, `userId`, `deviceId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md)[] \| `null`\>

Retrieve all sender key states (current + previous) for a group member device.

First element is the current state; remaining are previous states.

#### Parameters

##### groupId

`string`

Group identifier

##### userId

`string`

User identifier

##### deviceId

`number`

Device identifier

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md)[] \| `null`\>

Array of states, or null if none exist

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`getSenderKeyRecord`](ISenderKeyStore.md#getsenderkeyrecord)

***

### getSesameDeviceIds()

> **getSesameDeviceIds**(`userId`): `Promise`\<`number`[]\>

Get all device IDs for a specific user.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`number`[]\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`getSesameDeviceIds`](ISesameStore.md#getsesamedeviceids)

***

### getSessionCount()

> **getSessionCount**(): `Promise`\<`number`\>

Get the count of active sessions.

#### Returns

`Promise`\<`number`\>

Number of sessions stored

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getSessionCount`](IProtocolStore.md#getsessioncount)

***

### getSessionRecord()

> **getSessionRecord**(`address`): `Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

Retrieve session record.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

SessionRecord or null if no session exists

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getSessionRecord`](IProtocolStore.md#getsessionrecord)

***

### getSessionsForUser()

> **getSessionsForUser**(`userId`): `Promise`\<[`SessionRecord`](SessionRecord.md)[]\>

Get all sessions for a user (across all their devices).

Useful for multi-device scenarios where one user has multiple devices.

#### Parameters

##### userId

`string`

User ID (not including device ID)

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md)[]\>

Array of session records for all of this user's devices

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`getSessionsForUser`](IProtocolStore.md#getsessionsforuser)

***

### getSkippedSenderKey()

> **getSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`): `Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

Retrieve skipped message key for out-of-order decryption.

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

##### chainIndex

`number`

The message index to look up

#### Returns

`Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

Message key or null if not found/expired

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`getSkippedSenderKey`](ISenderKeyStore.md#getskippedsenderkey)

***

### getUserRecord()

> **getUserRecord**(`userId`): `Promise`\<[`UserRecord`](UserRecord.md) \| `null`\>

Get user record containing all devices for a user.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<[`UserRecord`](UserRecord.md) \| `null`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`getUserRecord`](ISesameStore.md#getuserrecord)

***

### hasIdentityKey()

> **hasIdentityKey**(`identityType?`): `Promise`\<`boolean`\>

Check if identity key exists.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`boolean`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`hasIdentityKey`](IProtocolStore.md#hasidentitykey)

***

### hasSession()

> **hasSession**(`address`): `Promise`\<`boolean`\>

Check if a session exists for the given address.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<`boolean`\>

true if session exists

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`hasSession`](IProtocolStore.md#hassession)

***

### isTrustedIdentity()

> **isTrustedIdentity**(`address`, `identity`, `direction`, `identityType?`): `Promise`\<`boolean`\>

Check if a contact's identity key is trusted.

Trust verification behavior depends on direction:
- SENDING: Stricter - don't send to untrusted identities
- RECEIVING: More permissive - allow receiving but warn user

From Signal Protocol:
"It's safer to receive from an unknown identity than to send to one"

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Complete composite identity candidate

##### direction

[`TrustDirection`](../enumerations/TrustDirection.md)

Whether we're sending or receiving

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

ACI or PNI trust namespace

#### Returns

`Promise`\<`boolean`\>

true if identity is trusted

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`isTrustedIdentity`](IProtocolStore.md#istrustedidentity)

***

### markKyberPreKeyUsed()

> **markKyberPreKeyUsed**(`kyberPreKeyId`, `signedPreKeyId`, `baseKeyBytes`, `identityType?`): `Promise`\<`void`\>

Mark a Kyber prekey as used.

Kyber prekeys can be reused (unlike one-time prekeys) but should be
tracked to ensure proper rotation.

#### Parameters

##### kyberPreKeyId

`number`

ID of the Kyber prekey that was used

##### signedPreKeyId

`number`

ID of the signed prekey used in combination

##### baseKeyBytes

`Uint8Array`

Base key bytes for the session

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`markKyberPreKeyUsed`](IProtocolStore.md#markkyberprekeyused)

***

### removeEcOneTimePreKey()

> **removeEcOneTimePreKey**(`preKeyId`, `identityType?`): `Promise`\<`void`\>

Remove an EC one-time prekey after it has been used.

#### Parameters

##### preKeyId

`number`

ID of the prekey to remove

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`removeEcOneTimePreKey`](IProtocolStore.md#removeeconetimeprekey)

***

### removeEcSignedPreKey()?

> `optional` **removeEcSignedPreKey**(`keyId`, `identityType?`): `Promise`\<`void`\>

Remove an EC signed prekey by ID.

Called during cleanup to remove expired archived prekeys.
Should NEVER remove the current (most recent) EC signed prekey.

#### Parameters

##### keyId

`number`

The key ID to remove

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`removeEcSignedPreKey`](IProtocolStore.md#removeecsignedprekey)

***

### removeKemOneTimePreKey()

> **removeKemOneTimePreKey**(`keyId`, `identityType?`): `Promise`\<`void`\>

Remove a one-time KEM prekey after it has been used.

CRITICAL: Must be called immediately after successful decapsulation
to provide per-session post-quantum forward secrecy.

#### Parameters

##### keyId

`number`

ID of the prekey to remove

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`removeKemOneTimePreKey`](IProtocolStore.md#removekemonetimeprekey)

***

### resolveGroupForSenderKeyId()

> **resolveGroupForSenderKeyId**(`senderKeyId`, `userId`, `deviceId`): `Promise`\<`string` \| `null`\>

Resolve the group a sender key belongs to, given only the identifier that
travels on the wire.

A received group message names its sender key by `senderKeyId` and nothing
else — the identifier is opaque, and the envelope no longer carries a
group. This is the receiver's only way back to a group, so it is what
decides which sender key state to decrypt against.

Searches previous states as well as current ones. A message encrypted just
before a rotation is still in flight when the rotation lands, and its
`senderKeyId` names the superseded key; resolving only against current
state would strand exactly the messages the rotation window exists to
cover.

#### Parameters

##### senderKeyId

`string`

Opaque identifier read from the SenderKeyMessage frame

##### userId

`string`

Sender user identifier, from the envelope

##### deviceId

`number`

Sender device identifier, from the envelope

#### Returns

`Promise`\<`string` \| `null`\>

The group ID, or null if this device has no such sender key

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`resolveGroupForSenderKeyId`](ISenderKeyStore.md#resolvegroupforsenderkeyid)

***

### saveContactIdentity()

> **saveContactIdentity**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`IdentityKeyChange`](../enumerations/IdentityKeyChange.md)\>

Save a contact's identity key and detect changes.

This is used for Trust On First Use (TOFU) and post-pinning change
detection. Returns whether either composite component changed.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Contact's complete canonical composite identity

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

ACI or PNI trust namespace

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

Optional redundant commitment that must match

#### Returns

`Promise`\<[`IdentityKeyChange`](../enumerations/IdentityKeyChange.md)\>

IdentityKeyChange indicating if key is new or changed

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`saveContactIdentity`](IProtocolStore.md#savecontactidentity)

***

### setDeviceRecord()

> **setDeviceRecord**(`userId`, `deviceId`, `record`): `Promise`\<`void`\>

Store device record.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### record

[`DeviceRecord`](DeviceRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`setDeviceRecord`](ISesameStore.md#setdevicerecord)

***

### setDeviceSession()

> **setDeviceSession**(`userId`, `deviceId`, `session`): `Promise`\<`void`\>

Set the session for a device.
This updates DeviceRecord.session.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### session

[`SessionRecord`](SessionRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`setDeviceSession`](ISesameStore.md#setdevicesession)

***

### setLocalRegistrationId()

> **setLocalRegistrationId**(`id`, `identityType?`): `Promise`\<`void`\>

Set our local registration ID.

Should only be called once during initialization.

#### Parameters

##### id

`number`

Registration ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`setLocalRegistrationId`](IProtocolStore.md#setlocalregistrationid)

***

### setMetadata()

> **setMetadata**(`key`, `value`): `Promise`\<`void`\>

Set a metadata value by key.

#### Parameters

##### key

`string`

##### value

`string`

#### Returns

`Promise`\<`void`\>

***

### setUserRecord()

> **setUserRecord**(`userId`, `record`): `Promise`\<`void`\>

Store user record.

#### Parameters

##### userId

`string`

##### record

[`UserRecord`](UserRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISesameStore`](ISesameStore.md).[`setUserRecord`](ISesameStore.md#setuserrecord)

***

### storeEcOneTimePreKeys()

> **storeEcOneTimePreKeys**(`prekeys`, `identityType?`): `Promise`\<`void`\>

Store EC one-time prekeys.

#### Parameters

##### prekeys

[`EcOneTimePreKey`](EcOneTimePreKey.md)[]

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeEcOneTimePreKeys`](IProtocolStore.md#storeeconetimeprekeys)

***

### storeEcSignedPreKey()

> **storeEcSignedPreKey**(`signedPreKey`, `identityType?`): `Promise`\<`void`\>

Store EC signed prekey.

When storing a new EC signed prekey (rotation), the old one should be
archived (not deleted) to handle in-flight messages.

#### Parameters

##### signedPreKey

[`EcSignedPreKey`](EcSignedPreKey.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeEcSignedPreKey`](IProtocolStore.md#storeecsignedprekey)

***

### storeIdentityKey()

> **storeIdentityKey**(`keyPair`, `identityType?`): `Promise`\<`void`\>

Store our identity key pair (only done once per install per identity type).

#### Parameters

##### keyPair

[`IdentityKeyPair`](IdentityKeyPair.md)

Identity key pair to store

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeIdentityKey`](IProtocolStore.md#storeidentitykey)

***

### storeKemOneTimePreKeys()

> **storeKemOneTimePreKeys**(`prekeys`, `identityType?`): `Promise`\<`void`\>

Store one-time KEM prekeys (batch storage).

#### Parameters

##### prekeys

[`KemOneTimePreKey`](../namespaces/keys/interfaces/KemOneTimePreKey.md)[]

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeKemOneTimePreKeys`](IProtocolStore.md#storekemonetimeprekeys)

***

### storeKyberPreKey()

> **storeKyberPreKey**(`kyberPreKey`, `identityType?`): `Promise`\<`void`\>

Store Kyber prekey (post-quantum security).

#### Parameters

##### kyberPreKey

[`KyberPreKey`](KyberPreKey.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeKyberPreKey`](IProtocolStore.md#storekyberprekey)

***

### storeMessageRecord()

> **storeMessageRecord**(`record`): `Promise`\<`void`\>

Store a message record after encryption

#### Parameters

##### record

[`MessageRecord`](MessageRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

`IMessageRecordStore.storeMessageRecord`

***

### storeSenderKey()

> **storeSenderKey**(`groupId`, `userId`, `deviceId`, `state`): `Promise`\<`void`\>

Store sender key state for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

##### state

[`SenderKeyState`](SenderKeyState.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`storeSenderKey`](ISenderKeyStore.md#storesenderkey)

***

### storeSenderKeyRecord()

> **storeSenderKeyRecord**(`groupId`, `userId`, `deviceId`, `states`): `Promise`\<`void`\>

Store all sender key states (current + previous) for a group member device.

The first element is the current state; remaining are previous states
retained during the rotation window for decrypting in-flight messages.

Per Sender Keys spec Section 5.1: "Implementations MUST store sender key
state persistently." This method persists the full record atomically.

#### Parameters

##### groupId

`string`

Group identifier

##### userId

`string`

User identifier

##### deviceId

`number`

Device identifier

##### states

[`SenderKeyState`](SenderKeyState.md)[]

Array of states (current first, then previous, capped at MAX_SENDER_KEY_STATES)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`storeSenderKeyRecord`](ISenderKeyStore.md#storesenderkeyrecord)

***

### storeSessionRecord()

> **storeSessionRecord**(`address`, `record`): `Promise`\<`void`\>

Store session record with current + archived sessions.

This is the preferred API for session storage, supporting session archiving
and handling race conditions.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address for this session

##### record

[`SessionRecord`](SessionRecord.md)

SessionRecord containing current and archived sessions

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`storeSessionRecord`](IProtocolStore.md#storesessionrecord)

***

### storeSkippedSenderKey()

> **storeSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`, `messageKey`): `Promise`\<`void`\>

Store skipped message key for out-of-order decryption.

When chain is advanced past a message (gap in chainIndex),
store the derived key so the skipped message can be decrypted later.

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

##### chainIndex

`number`

The message index this key is for

##### messageKey

[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md)

Derived IV and cipher key (base64 encoded)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ISenderKeyStore`](ISenderKeyStore.md).[`storeSkippedSenderKey`](ISenderKeyStore.md#storeskippedsenderkey)

***

### verifyContactIdentity()

> **verifyContactIdentity**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Promote the exact current tuple after authenticated comparison.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

#### Inherited from

[`IProtocolStore`](IProtocolStore.md).[`verifyContactIdentity`](IProtocolStore.md#verifycontactidentity)
