[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolLocalStore

# Interface: SignalProtocolLocalStore

Signal Protocol local store interface.

Canonical device/browser-local persistence for Signal Protocol state:
- identity keys and registrations
- sessions and sender keys
- SESAME multi-device state
- message records and local metadata

This is the interface that local store adapters should implement.

## Extends

- [`ProtocolStore`](ProtocolStore.md).[`SesameStore`](SesameStore.md).[`SenderKeyStore`](SenderKeyStore.md).[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).`MessageRecordStore`.`SendLogStore`

## Properties

### protection

> `readonly` **protection**: `LocalStoreProtection`

How this store protects its data at rest, and where its key is kept.

***

### storeIdentity?

> `readonly` `optional` **storeIdentity?**: `string`

The name of the stored data, the same in every tab, worker, and thread
of the origin that opens that data. When it is set and
`navigator.locks.request` exists, the client takes its session locks and
group-send locks as Web Locks under this name, so those contexts do not
change one session or one sender key at the same time. Without it, the
locks order the clients of one store object in one JavaScript context
only. The web SQLite store and the IndexedDB store give their database
names.

## Methods

### acceptContactIdentityRotation()

> **acceptContactIdentityRotation**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Explicitly accept a changed tuple and atomically delete every session for
that user. The previous tuple becomes rollback history.

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

[`ProtocolStore`](ProtocolStore.md).[`acceptContactIdentityRotation`](ProtocolStore.md#acceptcontactidentityrotation)

***

### acceptContactIdentityRotationAndDeleteSessions()

> **acceptContactIdentityRotationAndDeleteSessions**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Atomically rotate one per-user identity tuple and delete every bound
device session. The same write deletes the sender-key handoff rows of
every device of the account.

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

[`ProtocolStore`](ProtocolStore.md).[`acceptContactIdentityRotationAndDeleteSessions`](ProtocolStore.md#acceptcontactidentityrotationanddeletesessions)

***

### appendSendLogRecipients()

> **appendSendLogRecipients**(`clientMessageId`, `recipients`): `Promise`\<`void`\>

Add recipient rows to an entry. An existing row is kept unchanged. With
no entry, nothing is written.

#### Parameters

##### clientMessageId

`string`

##### recipients

readonly `SendLogDevice`[]

#### Returns

`Promise`\<`void`\>

#### Inherited from

`SendLogStore.appendSendLogRecipients`

***

### archiveCurrentSession()

> **archiveCurrentSession**(`address`, `newSession?`): `Promise`\<`void`\>

Archive the current session and optionally start a new one.

Used when:
- Identity key changes (possible MITM)
- Registration ID changes (app reinstall detected)
- Manual session reset

The same write deletes the sender-key handoff rows of the device in every
group.

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

[`ProtocolStore`](ProtocolStore.md).[`archiveCurrentSession`](ProtocolStore.md#archivecurrentsession)

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

[`SesameStore`](SesameStore.md).[`cleanupExpiredSessions`](SesameStore.md#cleanupexpiredsessions)

***

### clearAllKeys()

> **clearAllKeys**(): `Promise`\<`void`\>

Clear all encryption keys (use with caution!).

Use this only for:
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

`MessageRecordStore.clearAllMessageRecords`

***

### clearAllSessions()

> **clearAllSessions**(): `Promise`\<`void`\>

Clear all sessions from storage.
Used during force key reset.

#### Returns

`Promise`\<`void`\>

***

### clearSendLog()

> **clearSendLog**(): `Promise`\<`number`\>

Delete every entry and resend job. Returns the number of deleted entries.

#### Returns

`Promise`\<`number`\>

#### Inherited from

`SendLogStore.clearSendLog`

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

[`ProtocolStore`](ProtocolStore.md).[`commitSessionTrust`](ProtocolStore.md#commitsessiontrust)

***

### compareAndSetMetadata()

> **compareAndSetMetadata**(`key`, `expected`, `value`): `Promise`\<`boolean`\>

Compare and replace one metadata value in the backing store's atomic write.
Null means absent or deletion. Return false without writing on a mismatch.
Reads and comparisons must use current backing state, not an adapter cache.

#### Parameters

##### key

`string`

##### expected

`string` \| `null`

##### value

`string` \| `null`

#### Returns

`Promise`\<`boolean`\>

***

### completeReceiveWork()

> **completeReceiveWork**(`workId`, `expectedRevision`, `metadata?`): `Promise`\<`boolean`\>

Delete one receive record and apply the metadata writes in one atomic
write. Return false without writing when the stored revision is not
`expectedRevision`.

#### Parameters

##### workId

`string`

##### expectedRevision

`number`

##### metadata?

readonly `ReceiveWorkMetadataWrite`[]

#### Returns

`Promise`\<`boolean`\>

***

### completeResendJob()

> **completeResendJob**(`jobId`, `state`): `Promise`\<`void`\>

Set the final state of a resend job. With no job, nothing is written.

#### Parameters

##### jobId

`string`

##### state

`"abandoned"` \| `"posted"`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`SendLogStore.completeResendJob`

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

[`SenderKeyStore`](SenderKeyStore.md).[`countSkippedSenderKeys`](SenderKeyStore.md#countskippedsenderkeys)

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

Delete all sender keys, skipped sender message keys, and sender-key
handoff rows for a group (when the caller deletes the group), in one
write. Returns the number of sender keys deleted.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`deleteAllSenderKeysForGroup`](SenderKeyStore.md#deleteallsenderkeysforgroup)

***

### deleteDeviceRecord()

> **deleteDeviceRecord**(`userId`, `deviceId`): `Promise`\<`void`\>

Delete device record. The same write deletes the sender-key handoff rows
of the device in every group.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SesameStore`](SesameStore.md).[`deleteDeviceRecord`](SesameStore.md#deletedevicerecord)

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

`MessageRecordStore.deleteExpiredMessageRecords`

***

### deleteExpiredSendLog()

> **deleteExpiredSendLog**(`maxAgeMs`): `Promise`\<`number`\>

Delete each entry, and each resend job, that the store wrote more than
`maxAgeMs` ago. Returns the number of deleted entries.

#### Parameters

##### maxAgeMs

`number`

#### Returns

`Promise`\<`number`\>

#### Inherited from

`SendLogStore.deleteExpiredSendLog`

***

### deleteMessageRecord()

> **deleteMessageRecord**(`sessionId`, `timestamp`): `Promise`\<`void`\>

Delete a message record by session and timestamp.

The client calls it after an E2EE delivery receipt from the recipient
device, for an expired record at a retry request, and for a record that
it must not resend: a null message, or a sender key distribution alone.

#### Parameters

##### sessionId

`string`

##### timestamp

`number`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`MessageRecordStore.deleteMessageRecord`

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

`MessageRecordStore.deleteMessageRecordsForSession`

***

### deleteMetadata()

> **deleteMetadata**(`key`): `Promise`\<`void`\>

Delete one metadata value.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`void`\>

***

### deleteOldestSkippedSenderKeys()

> **deleteOldestSkippedSenderKeys**(`groupId`, `senderId`, `senderDeviceId`, `count`): `Promise`\<`number`\>

Delete oldest skipped keys to make room for new ones.

The store calls this when the chain reaches the maxSkippedKeys limit.

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

[`SenderKeyStore`](SenderKeyStore.md).[`deleteOldestSkippedSenderKeys`](SenderKeyStore.md#deleteoldestskippedsenderkeys)

***

### deleteSenderKey()

> **deleteSenderKey**(`groupId`, `userId`, `deviceId`, `options?`): `Promise`\<`void`\>

Delete sender key for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

##### options?

[`SenderKeyRecordWriteOptions`](SenderKeyRecordWriteOptions.md)

With `deleteSenderKeyHandoffs`, the same write deletes
  every sender-key handoff row of the group. The manager sets it when it
  deletes the local device's own key.

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`deleteSenderKey`](SenderKeyStore.md#deletesenderkey)

***

### deleteSendLogEntry()

> **deleteSendLogEntry**(`clientMessageId`): `Promise`\<`boolean`\>

Delete one entry and its rows. Returns true when an entry was deleted.

#### Parameters

##### clientMessageId

`string`

#### Returns

`Promise`\<`boolean`\>

#### Inherited from

`SendLogStore.deleteSendLogEntry`

***

### deleteSendLogRecipient()

> **deleteSendLogRecipient**(`clientMessageId`, `recipient`): `Promise`\<`boolean`\>

Delete the row of one device. When no row remains and the send is
finished, the payload is deleted. Returns true when a row was deleted.

#### Parameters

##### clientMessageId

`string`

##### recipient

`SendLogDevice`

#### Returns

`Promise`\<`boolean`\>

#### Inherited from

`SendLogStore.deleteSendLogRecipient`

***

### deleteSendLogRecipientsByTimestamp()

> **deleteSendLogRecipientsByTimestamp**(`recipient`, `clientTimestamps`): `Promise`\<`number`\>

Delete the rows of one device at each of the client timestamps, with the
same payload rule as `deleteSendLogRecipient`. Returns the number of
deleted rows.

#### Parameters

##### recipient

`SendLogDevice`

##### clientTimestamps

readonly `number`[]

#### Returns

`Promise`\<`number`\>

#### Inherited from

`SendLogStore.deleteSendLogRecipientsByTimestamp`

***

### deleteSessionRecord()

> **deleteSessionRecord**(`address`): `Promise`\<`void`\>

Delete session record. The same write deletes the sender-key handoff
rows of the device in every group.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`deleteSessionRecord`](ProtocolStore.md#deletesessionrecord)

***

### deleteSkippedSenderKey()

> **deleteSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `senderKeyId`, `chainIndex`): `Promise`\<`void`\>

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

##### senderKeyId

`string`

Distribution identifier for this sender-key generation

##### chainIndex

`number`

The message index to delete

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`deleteSkippedSenderKey`](SenderKeyStore.md#deleteskippedsenderkey)

***

### deleteStaleRecords()

> **deleteStaleRecords**(`maxLatency`): `Promise`\<`number`\>

Delete the stale device records with their sessions. A record is stale
when it has no session and is older than `maxLatency`, or when it is
marked removed and its removal is older than `maxLatency`
(`isExpiredRemovedDevice`). A user record with no device left goes too.

#### Parameters

##### maxLatency

`number`

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`SesameStore`](SesameStore.md).[`deleteStaleRecords`](SesameStore.md#deletestalerecords)

***

### findSendLogEntries()

> **findSendLogEntries**(`recipient`, `clientTimestamp`): `Promise`\<`SendLogEntry`[]\>

Every entry for one device at one client timestamp, ordered by `clientMessageId`.

#### Parameters

##### recipient

`SendLogDevice`

##### clientTimestamp

`number`

#### Returns

`Promise`\<`SendLogEntry`[]\>

#### Inherited from

`SendLogStore.findSendLogEntries`

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

[`ProtocolStore`](ProtocolStore.md).[`getAllEcSignedPreKeys`](ProtocolStore.md#getallecsignedprekeys)

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

[`SenderKeyStore`](SenderKeyStore.md).[`getAllSenderKeysForGroup`](SenderKeyStore.md#getallsenderkeysforgroup)

***

### getAllUserIds()

> **getAllUserIds**(): `Promise`\<`string`[]\>

Get all user IDs with SESAME records.

#### Returns

`Promise`\<`string`[]\>

#### Inherited from

[`SesameStore`](SesameStore.md).[`getAllUserIds`](SesameStore.md#getalluserids)

***

### getContactIdentity()

> **getContactIdentity**(`address`, `identityType?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md) \| `null`\>

Get a contact's saved identity key.

Returns null if the store holds no identity key for this address.

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

[`ProtocolStore`](ProtocolStore.md).[`getContactIdentity`](ProtocolStore.md#getcontactidentity)

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

[`SesameStore`](SesameStore.md).[`getDeviceRecord`](SesameStore.md#getdevicerecord)

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

[`SesameStore`](SesameStore.md).[`getDeviceSession`](SesameStore.md#getdevicesession)

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

[`ProtocolStore`](ProtocolStore.md).[`getEcOneTimePreKeys`](ProtocolStore.md#geteconetimeprekeys)

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

[`ProtocolStore`](ProtocolStore.md).[`getEcSignedPreKey`](ProtocolStore.md#getecsignedprekey)

***

### getEcSignedPreKeyMaxId()

> **getEcSignedPreKeyMaxId**(`identityType?`): `Promise`\<`number`\>

Get the maximum EC signed prekey ID in storage.
Used to generate new keyIds that will not collide with existing ones.

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

[`ProtocolStore`](ProtocolStore.md).[`getIdentityKey`](ProtocolStore.md#getidentitykey)

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

[`ProtocolStore`](ProtocolStore.md).[`getKemOneTimePreKey`](ProtocolStore.md#getkemonetimeprekey)

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

[`ProtocolStore`](ProtocolStore.md).[`getKemOneTimePreKeyCount`](ProtocolStore.md#getkemonetimeprekeycount)

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

[`ProtocolStore`](ProtocolStore.md).[`getKemOneTimePreKeys`](ProtocolStore.md#getkemonetimeprekeys)

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

[`ProtocolStore`](ProtocolStore.md).[`getKyberPreKey`](ProtocolStore.md#getkyberprekey)

***

### getKyberPreKeyById()

> **getKyberPreKeyById**(`keyId`, `identityType?`): `Promise`\<`RetainedKyberPreKey` \| `null`\>

Retrieve the exact retained Kyber prekey instance named by a message.

#### Parameters

##### keyId

`number`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`RetainedKyberPreKey` \| `null`\>

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`getKyberPreKeyById`](ProtocolStore.md#getkyberprekeybyid)

***

### getKyberPreKeyMaxId()

> **getKyberPreKeyMaxId**(`identityType?`): `Promise`\<`number`\>

Get the maximum Kyber prekey ID in storage.
Used to generate new keyIds that will not collide with existing ones.

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
Detects session resets when the user reinstalls the app.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`getLocalRegistrationId`](ProtocolStore.md#getlocalregistrationid)

***

### getMessageRecord()

> **getMessageRecord**(`sessionId`, `timestamp`): `Promise`\<[`MessageRecord`](MessageRecord.md) \| `null`\>

Get a message record by session and timestamp (PRIMARY lookup method).

Per Signal Protocol, the client timestamp identifies a message.

#### Parameters

##### sessionId

`string`

##### timestamp

`number`

#### Returns

`Promise`\<[`MessageRecord`](MessageRecord.md) \| `null`\>

#### Inherited from

`MessageRecordStore.getMessageRecord`

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

### getPendingResendJobs()

> **getPendingResendJobs**(): `Promise`\<`SendLogResendJob`[]\>

Every `pending` resend job, ordered by `createdAt`, then `jobId`.

#### Returns

`Promise`\<`SendLogResendJob`[]\>

#### Inherited from

`SendLogStore.getPendingResendJobs`

***

### getReceiveWork()

> **getReceiveWork**(`workId`): `Promise`\<`ReceiveWorkRecord` \| `null`\>

Get one receive record, or null.

#### Parameters

##### workId

`string`

#### Returns

`Promise`\<`ReceiveWorkRecord` \| `null`\>

***

### getResendJob()

> **getResendJob**(`jobId`): `Promise`\<`SendLogResendJob` \| `null`\>

One resend job, or null.

#### Parameters

##### jobId

`string`

#### Returns

`Promise`\<`SendLogResendJob` \| `null`\>

#### Inherited from

`SendLogStore.getResendJob`

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

[`SenderKeyStore`](SenderKeyStore.md).[`getSenderKey`](SenderKeyStore.md#getsenderkey)

***

### getSenderKeyRecord()

> **getSenderKeyRecord**(`groupId`, `userId`, `deviceId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md)[] \| `null`\>

Retrieve all sender key states (current + previous) for a group member device.

First element is the current state. The remaining entries are previous states.

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

[`SenderKeyStore`](SenderKeyStore.md).[`getSenderKeyRecord`](SenderKeyStore.md#getsenderkeyrecord)

***

### getSendLogEntry()

> **getSendLogEntry**(`clientMessageId`, `recipient`): `Promise`\<`SendLogEntry` \| `null`\>

The entry of one send for one device, or null when the device has no row.

#### Parameters

##### clientMessageId

`string`

##### recipient

`SendLogDevice`

#### Returns

`Promise`\<`SendLogEntry` \| `null`\>

#### Inherited from

`SendLogStore.getSendLogEntry`

***

### getSendLogRecipients()

> **getSendLogRecipients**(`clientMessageId`): `Promise`\<`SendLogRecipient`[]\>

The remaining recipient rows of one send, ordered by user and device.

#### Parameters

##### clientMessageId

`string`

#### Returns

`Promise`\<`SendLogRecipient`[]\>

#### Inherited from

`SendLogStore.getSendLogRecipients`

***

### getSesameDeviceIds()

> **getSesameDeviceIds**(`userId`): `Promise`\<`number`[]\>

Get all device IDs for a specific user. The list includes the devices
whose record is marked removed. A caller that sends to the devices skips
them with `isRemovedDevice`.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`number`[]\>

#### Inherited from

[`SesameStore`](SesameStore.md).[`getSesameDeviceIds`](SesameStore.md#getsesamedeviceids)

***

### getSessionCount()

> **getSessionCount**(): `Promise`\<`number`\>

Get the count of active sessions.

#### Returns

`Promise`\<`number`\>

Number of sessions stored

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`getSessionCount`](ProtocolStore.md#getsessioncount)

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

[`ProtocolStore`](ProtocolStore.md).[`getSessionRecord`](ProtocolStore.md#getsessionrecord)

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

[`ProtocolStore`](ProtocolStore.md).[`getSessionsForUser`](ProtocolStore.md#getsessionsforuser)

***

### getSkippedSenderKey()

> **getSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `senderKeyId`, `chainIndex`): `Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

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

##### senderKeyId

`string`

Distribution identifier for this sender-key generation

##### chainIndex

`number`

The message index to look up

#### Returns

`Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

Message key or null if not found/expired

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`getSkippedSenderKey`](SenderKeyStore.md#getskippedsenderkey)

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

[`SesameStore`](SesameStore.md).[`getUserRecord`](SesameStore.md#getuserrecord)

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

[`ProtocolStore`](ProtocolStore.md).[`hasIdentityKey`](ProtocolStore.md#hasidentitykey)

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

[`ProtocolStore`](ProtocolStore.md).[`hasSession`](ProtocolStore.md#hassession)

***

### incrementSendLogResendCount()

> **incrementSendLogResendCount**(`clientMessageId`, `recipient`): `Promise`\<`number` \| `null`\>

Add one to the resend count of a row. Returns the new count, or null
when the device has no row.

#### Parameters

##### clientMessageId

`string`

##### recipient

`SendLogDevice`

#### Returns

`Promise`\<`number` \| `null`\>

#### Inherited from

`SendLogStore.incrementSendLogResendCount`

***

### invalidateAccountSenderKeyHandoffs()

> **invalidateAccountSenderKeyHandoffs**(`userId`): `Promise`\<`boolean`\>

Delete the rows of every device of one account in every group, as an
identity rotation of the account does.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`boolean`\>

True when at least one row was deleted

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`invalidateAccountSenderKeyHandoffs`](SenderKeyHandoffStore.md#invalidateaccountsenderkeyhandoffs)

***

### invalidateSenderKeyHandoff()

> **invalidateSenderKeyHandoff**(`groupId`, `device`): `Promise`\<`boolean`\>

Delete the rows of one device in one group.

#### Parameters

##### groupId

`string`

##### device

[`SenderKeyHandoffDevice`](SenderKeyHandoffDevice.md)

#### Returns

`Promise`\<`boolean`\>

True when at least one row was deleted

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`invalidateSenderKeyHandoff`](SenderKeyHandoffStore.md#invalidatesenderkeyhandoff)

***

### isTrustedIdentity()

> **isTrustedIdentity**(`address`, `identity`, `direction`, `identityType?`): `Promise`\<`boolean`\>

Check whether the store trusts a contact's identity key.

Trust verification behavior depends on direction:
- SENDING: Stricter - do not send to untrusted identities
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

Whether the local device sends or receives

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

ACI or PNI trust namespace

#### Returns

`Promise`\<`boolean`\>

true if the store trusts the identity

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`isTrustedIdentity`](ProtocolStore.md#istrustedidentity)

***

### listReceiveWork()

> **listReceiveWork**(`query?`): `Promise`\<`ReceiveWorkRecord`[]\>

List receive records in ascending `(arrivalSeq, workId)` order. The
order compares `workId` values by UTF-16 code unit. With `after`, a
record passes when its `arrivalSeq` is above the cursor `arrivalSeq`,
or equal to it with a `workId` above the cursor `workId`. Return at
most `limit` records, 100 when not set.

#### Parameters

##### query?

`ReceiveWorkQuery`

#### Returns

`Promise`\<`ReceiveWorkRecord`[]\>

***

### listSenderKeyHandoffGroupIds()

> **listSenderKeyHandoffGroupIds**(): `Promise`\<`string`[]\>

The distinct group IDs that hold rows. For the sweep only.

#### Returns

`Promise`\<`string`[]\>

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`listSenderKeyHandoffGroupIds`](SenderKeyHandoffStore.md#listsenderkeyhandoffgroupids)

***

### listSenderKeyHandoffs()

> **listSenderKeyHandoffs**(`groupId`, `generation`): `Promise`\<[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)[]\>

The rows of one group at one generation.

#### Parameters

##### groupId

`string`

##### generation

`number`

#### Returns

`Promise`\<[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)[]\>

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`listSenderKeyHandoffs`](SenderKeyHandoffStore.md#listsenderkeyhandoffs)

***

### markKyberPreKeyUsed()

> **markKyberPreKeyUsed**(`kyberPreKeyId`, `signedPreKeyId`, `baseKeyBytes`, `identityType?`): `Promise`\<`void`\>

Mark a Kyber prekey as used.

Callers may reuse Kyber prekeys (unlike one-time prekeys), and the store
must track them so rotation stays correct.

#### Parameters

##### kyberPreKeyId

`number`

ID of the Kyber prekey the session used

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

[`ProtocolStore`](ProtocolStore.md).[`markKyberPreKeyUsed`](ProtocolStore.md#markkyberprekeyused)

***

### markSendLogComplete()

> **markSendLogComplete**(`clientMessageId`): `Promise`\<`void`\>

Mark the send finished. When no recipient row remains, the payload is
deleted.

#### Parameters

##### clientMessageId

`string`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`SendLogStore.markSendLogComplete`

***

### putReceiveWork()

> **putReceiveWork**(`record`, `expectedRevision`): `Promise`\<`boolean`\>

Write one receive record. With `expectedRevision` null, the write
inserts and fails when a record exists. Otherwise it replaces the record
with that revision. Return false without writing on a mismatch.

#### Parameters

##### record

`ReceiveWorkRecord`

##### expectedRevision

`number` \| `null`

#### Returns

`Promise`\<`boolean`\>

***

### receiveWorkUsage()

> **receiveWorkUsage**(`query?`): `Promise`\<`ReceiveWorkUsage`\>

Count receive records. With `groupId`, count only the records of that
group that wait for a group update.

#### Parameters

##### query?

###### groupId?

`string`

#### Returns

`Promise`\<`ReceiveWorkUsage`\>

***

### recordSenderKeyHandoff()

> **recordSenderKeyHandoff**(`record`): `Promise`\<`void`\>

Insert or replace the row keyed by group, sender key ID, generation,
recipient user, recipient device, and recipient registration ID.

#### Parameters

##### record

[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`recordSenderKeyHandoff`](SenderKeyHandoffStore.md#recordsenderkeyhandoff)

***

### removeEcOneTimePreKey()

> **removeEcOneTimePreKey**(`preKeyId`, `identityType?`): `Promise`\<`void`\>

Remove an EC one-time prekey after a session uses it.

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

[`ProtocolStore`](ProtocolStore.md).[`removeEcOneTimePreKey`](ProtocolStore.md#removeeconetimeprekey)

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

[`ProtocolStore`](ProtocolStore.md).[`removeEcSignedPreKey`](ProtocolStore.md#removeecsignedprekey)

***

### removeKemOneTimePreKey()

> **removeKemOneTimePreKey**(`keyId`, `identityType?`): `Promise`\<`void`\>

Remove a one-time KEM prekey after a session uses it.

CRITICAL: Call this immediately after successful decapsulation
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

[`ProtocolStore`](ProtocolStore.md).[`removeKemOneTimePreKey`](ProtocolStore.md#removekemonetimeprekey)

***

### resolveGroupForSenderKeyId()

> **resolveGroupForSenderKeyId**(`senderKeyId`, `userId`, `deviceId`): `Promise`\<`string` \| `null`\>

Resolve the group a sender key belongs to, given only the identifier that
travels on the wire.

A received group message names its sender key by `senderKeyId` and nothing
else. The identifier is opaque, and the envelope no longer carries a
group. This is the receiver's only way back to a group, so it is what
decides which sender key state to decrypt against.

Searches previous states as well as current ones. A message encrypted just
before a rotation is still in flight when the rotation lands, and its
`senderKeyId` names the superseded key. Resolving only against current
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

[`SenderKeyStore`](SenderKeyStore.md).[`resolveGroupForSenderKeyId`](SenderKeyStore.md#resolvegroupforsenderkeyid)

***

### retainSenderKeyHandoffs()

> **retainSenderKeyHandoffs**(`groupId`, `senderKeyId`): `Promise`\<`number`\>

Delete the rows of a group whose sender key ID differs from the given one.
Null deletes every row of the group.

#### Parameters

##### groupId

`string`

##### senderKeyId

`string` \| `null`

#### Returns

`Promise`\<`number`\>

The number of deleted rows

#### Inherited from

[`SenderKeyHandoffStore`](SenderKeyHandoffStore.md).[`retainSenderKeyHandoffs`](SenderKeyHandoffStore.md#retainsenderkeyhandoffs)

***

### rewriteMessageRecords()

> **rewriteMessageRecords**(`rewrite`): `Promise`\<`number`\>

Rewrite the plaintext of each record. `rewrite` returns the plaintext to
keep: the same string leaves the record as it is, another string
replaces the plaintext, and null deletes the record. A replaced record
keeps its `createdAt` and every other field. A record that another
write replaces between the read and the rewrite stays as that write
left it.

#### Parameters

##### rewrite

(`record`) => `string` \| `null`

#### Returns

`Promise`\<`number`\>

The number of records replaced or deleted

#### Inherited from

`MessageRecordStore.rewriteMessageRecords`

***

### saveContactIdentity()

> **saveContactIdentity**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`IdentityKeyChange`](../enumerations/IdentityKeyChange.md)\>

Save a contact's identity key and detect changes.

This supports Trust On First Use (TOFU) and post-pinning change
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

[`ProtocolStore`](ProtocolStore.md).[`saveContactIdentity`](ProtocolStore.md#savecontactidentity)

***

### setDeviceRecord()

> **setDeviceRecord**(`userId`, `deviceId`, `record`, `options?`): `Promise`\<`void`\>

Store device record.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### record

[`DeviceRecord`](DeviceRecord.md)

##### options?

[`SetDeviceRecordOptions`](SetDeviceRecordOptions.md)

With `senderKeyHandoffInvalidation`, the same write
  deletes the sender-key handoff rows of that device in every group

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SesameStore`](SesameStore.md).[`setDeviceRecord`](SesameStore.md#setdevicerecord)

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

[`SesameStore`](SesameStore.md).[`setDeviceSession`](SesameStore.md#setdevicesession)

***

### setLocalRegistrationId()

> **setLocalRegistrationId**(`id`, `identityType?`): `Promise`\<`void`\>

Set our local registration ID.

Call this only once, during initialization.

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

[`ProtocolStore`](ProtocolStore.md).[`setLocalRegistrationId`](ProtocolStore.md#setlocalregistrationid)

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

[`SesameStore`](SesameStore.md).[`setUserRecord`](SesameStore.md#setuserrecord)

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

[`ProtocolStore`](ProtocolStore.md).[`storeEcOneTimePreKeys`](ProtocolStore.md#storeeconetimeprekeys)

***

### storeEcSignedPreKey()

> **storeEcSignedPreKey**(`signedPreKey`, `identityType?`): `Promise`\<`void`\>

Store EC signed prekey.

When storing a new EC signed prekey (rotation), archive the old one
instead of deleting it, to handle in-flight messages.

#### Parameters

##### signedPreKey

[`EcSignedPreKey`](EcSignedPreKey.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`ProtocolStore`](ProtocolStore.md).[`storeEcSignedPreKey`](ProtocolStore.md#storeecsignedprekey)

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

[`ProtocolStore`](ProtocolStore.md).[`storeIdentityKey`](ProtocolStore.md#storeidentitykey)

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

[`ProtocolStore`](ProtocolStore.md).[`storeKemOneTimePreKeys`](ProtocolStore.md#storekemonetimeprekeys)

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

[`ProtocolStore`](ProtocolStore.md).[`storeKyberPreKey`](ProtocolStore.md#storekyberprekey)

***

### storeMessageRecord()

> **storeMessageRecord**(`record`): `Promise`\<`void`\>

Store a message record after encryption. A record with the same
`sessionId` and `timestamp` is replaced. The store sets `createdAt` from
its clock on the first write and keeps that value on a replace, so the
value in `record` is not stored and a resend does not extend retention.

#### Parameters

##### record

[`MessageRecord`](MessageRecord.md)

#### Returns

`Promise`\<`void`\>

#### Inherited from

`MessageRecordStore.storeMessageRecord`

***

### storeResendJob()

> **storeResendJob**(`job`): `Promise`\<`void`\>

Store a resend job. A job with the same `jobId` is replaced. The store
sets `createdAt` from its clock on the first write and keeps that value
on a replace, so the value in `job` is not stored.

#### Parameters

##### job

`SendLogResendJob`

#### Returns

`Promise`\<`void`\>

#### Inherited from

`SendLogStore.storeResendJob`

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

[`SenderKeyStore`](SenderKeyStore.md).[`storeSenderKey`](SenderKeyStore.md#storesenderkey)

***

### storeSenderKeyRecord()

> **storeSenderKeyRecord**(`groupId`, `userId`, `deviceId`, `states`, `receive?`, `options?`): `Promise`\<`void`\>

Store all sender key states (current + previous) for a group member device.

The first element is the current state. The remaining entries are previous states
retained during the rotation window for decrypting in-flight messages.

Per Sender Keys spec Section 5.1: "Implementations MUST store sender key
state persistently." This method persists the full record atomically with
every receive effect. A rejection preserves the prior record, skipped keys,
and received content. The same guarantee applies without a content receipt.

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

##### receive?

`SenderKeyReceiveCommit`

The receive effects to commit with the record

##### options?

[`SenderKeyRecordWriteOptions`](SenderKeyRecordWriteOptions.md)

With `deleteSenderKeyHandoffs`, the same write deletes
  every sender-key handoff row of the group. The manager sets it when it
  writes a new own key.

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`storeSenderKeyRecord`](SenderKeyStore.md#storesenderkeyrecord)

***

### storeSendLogEntry()

> **storeSendLogEntry**(`payload`, `recipients`): `Promise`\<`void`\>

Store a send log entry and its recipient rows in one transaction. An
entry with the same `clientMessageId` is replaced with its rows.

#### Parameters

##### payload

`NewSendLogPayload`

##### recipients

readonly `SendLogDevice`[]

#### Returns

`Promise`\<`void`\>

#### Inherited from

`SendLogStore.storeSendLogEntry`

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

[`ProtocolStore`](ProtocolStore.md).[`storeSessionRecord`](ProtocolStore.md#storesessionrecord)

***

### storeSkippedSenderKey()

> **storeSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `senderKeyId`, `chainIndex`, `messageKey`): `Promise`\<`void`\>

Store skipped message key for out-of-order decryption.

When the chain advances past a message (gap in chainIndex),
store the derived key so a later call can decrypt the skipped message.

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

##### senderKeyId

`string`

Distribution identifier for this sender-key generation

##### chainIndex

`number`

The message index this key is for

##### messageKey

[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md)

Derived IV and cipher key (base64 encoded)

#### Returns

`Promise`\<`void`\>

#### Inherited from

[`SenderKeyStore`](SenderKeyStore.md).[`storeSkippedSenderKey`](SenderKeyStore.md#storeskippedsenderkey)

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

[`ProtocolStore`](ProtocolStore.md).[`verifyContactIdentity`](ProtocolStore.md#verifycontactidentity)
