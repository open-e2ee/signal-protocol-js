[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IProtocolStore

# Interface: IProtocolStore

Aggregate protocol store interface.

Combines the five focused local-store responsibilities into one interface.

## Extends

- [`IIdentityKeyStore`](IIdentityKeyStore.md).[`IEcOneTimePreKeyStore`](IEcOneTimePreKeyStore.md).[`IEcSignedPreKeyStore`](IEcSignedPreKeyStore.md).[`IKyberLastResortPreKeyStore`](IKyberLastResortPreKeyStore.md).[`IKemPreKeyStore`](IKemPreKeyStore.md).[`ISessionStore`](ISessionStore.md)

## Extended by

- [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`acceptContactIdentityRotation`](IIdentityKeyStore.md#acceptcontactidentityrotation)

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

[`ISessionStore`](ISessionStore.md).[`archiveCurrentSession`](ISessionStore.md#archivecurrentsession)

***

### commitSessionTrust()

> **commitSessionTrust**(`commit`): `Promise`\<`void`\>

Atomically pin/match trust, store the session, and consume referenced one-time prekeys.

#### Parameters

##### commit

[`SessionTrustCommit`](SessionTrustCommit.md)

#### Returns

`Promise`\<`void`\>

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

[`ISessionStore`](ISessionStore.md).[`deleteSessionRecord`](ISessionStore.md#deletesessionrecord)

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

[`IEcSignedPreKeyStore`](IEcSignedPreKeyStore.md).[`getAllEcSignedPreKeys`](IEcSignedPreKeyStore.md#getallecsignedprekeys)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`getContactIdentity`](IIdentityKeyStore.md#getcontactidentity)

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

[`IEcOneTimePreKeyStore`](IEcOneTimePreKeyStore.md).[`getEcOneTimePreKeys`](IEcOneTimePreKeyStore.md#geteconetimeprekeys)

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

[`IEcSignedPreKeyStore`](IEcSignedPreKeyStore.md).[`getEcSignedPreKey`](IEcSignedPreKeyStore.md#getecsignedprekey)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`getIdentityKey`](IIdentityKeyStore.md#getidentitykey)

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

[`IKemPreKeyStore`](IKemPreKeyStore.md).[`getKemOneTimePreKey`](IKemPreKeyStore.md#getkemonetimeprekey)

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

[`IKemPreKeyStore`](IKemPreKeyStore.md).[`getKemOneTimePreKeyCount`](IKemPreKeyStore.md#getkemonetimeprekeycount)

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

[`IKemPreKeyStore`](IKemPreKeyStore.md).[`getKemOneTimePreKeys`](IKemPreKeyStore.md#getkemonetimeprekeys)

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

[`IKyberLastResortPreKeyStore`](IKyberLastResortPreKeyStore.md).[`getKyberPreKey`](IKyberLastResortPreKeyStore.md#getkyberprekey)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`getLocalRegistrationId`](IIdentityKeyStore.md#getlocalregistrationid)

***

### getSessionCount()

> **getSessionCount**(): `Promise`\<`number`\>

Get the count of active sessions.

#### Returns

`Promise`\<`number`\>

Number of sessions stored

#### Inherited from

[`ISessionStore`](ISessionStore.md).[`getSessionCount`](ISessionStore.md#getsessioncount)

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

[`ISessionStore`](ISessionStore.md).[`getSessionRecord`](ISessionStore.md#getsessionrecord)

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

[`ISessionStore`](ISessionStore.md).[`getSessionsForUser`](ISessionStore.md#getsessionsforuser)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`hasIdentityKey`](IIdentityKeyStore.md#hasidentitykey)

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

[`ISessionStore`](ISessionStore.md).[`hasSession`](ISessionStore.md#hassession)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`isTrustedIdentity`](IIdentityKeyStore.md#istrustedidentity)

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

[`IKyberLastResortPreKeyStore`](IKyberLastResortPreKeyStore.md).[`markKyberPreKeyUsed`](IKyberLastResortPreKeyStore.md#markkyberprekeyused)

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

[`IEcOneTimePreKeyStore`](IEcOneTimePreKeyStore.md).[`removeEcOneTimePreKey`](IEcOneTimePreKeyStore.md#removeeconetimeprekey)

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

[`IEcSignedPreKeyStore`](IEcSignedPreKeyStore.md).[`removeEcSignedPreKey`](IEcSignedPreKeyStore.md#removeecsignedprekey)

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

[`IKemPreKeyStore`](IKemPreKeyStore.md).[`removeKemOneTimePreKey`](IKemPreKeyStore.md#removekemonetimeprekey)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`saveContactIdentity`](IIdentityKeyStore.md#savecontactidentity)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`setLocalRegistrationId`](IIdentityKeyStore.md#setlocalregistrationid)

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

[`IEcOneTimePreKeyStore`](IEcOneTimePreKeyStore.md).[`storeEcOneTimePreKeys`](IEcOneTimePreKeyStore.md#storeeconetimeprekeys)

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

[`IEcSignedPreKeyStore`](IEcSignedPreKeyStore.md).[`storeEcSignedPreKey`](IEcSignedPreKeyStore.md#storeecsignedprekey)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`storeIdentityKey`](IIdentityKeyStore.md#storeidentitykey)

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

[`IKemPreKeyStore`](IKemPreKeyStore.md).[`storeKemOneTimePreKeys`](IKemPreKeyStore.md#storekemonetimeprekeys)

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

[`IKyberLastResortPreKeyStore`](IKyberLastResortPreKeyStore.md).[`storeKyberPreKey`](IKyberLastResortPreKeyStore.md#storekyberprekey)

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

[`ISessionStore`](ISessionStore.md).[`storeSessionRecord`](ISessionStore.md#storesessionrecord)

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

[`IIdentityKeyStore`](IIdentityKeyStore.md).[`verifyContactIdentity`](IIdentityKeyStore.md#verifycontactidentity)
