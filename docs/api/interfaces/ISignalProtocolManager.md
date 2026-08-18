[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISignalProtocolManager

# Interface: ISignalProtocolManager

Signal Protocol manager interface

## Methods

### cleanupExpiredKeys()

> **cleanupExpiredKeys**(`remoteAddress`): `Promise`\<`void`\>

Clean up expired message keys for a session

Signal Protocol Section 8.4 recommends deleting message keys older than
one week to avoid excessive storage. This method explicitly triggers cleanup.

Note: Cleanup also happens automatically during encrypt/decrypt operations.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

#### Returns

`Promise`\<`void`\>

***

### decrypt()

> **decrypt**(`remoteAddress`, `ciphertext`): `Promise`\<`string`\>

Decrypt a message using existing session

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

### encrypt()

> **encrypt**(`remoteAddress`, `plaintext`): `Promise`\<[`Ciphertext`](../type-aliases/Ciphertext.md)\>

Encrypt a message using existing session

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

### generatePreKeyBundle()

> **generatePreKeyBundle**(`userId`, `deviceId`, `identityType?`): `Promise`\<`void`\>

Generate and upload prekey bundle

#### Parameters

##### userId

`string`

Local user's ID

##### deviceId

`number`

Local device's ID (required, no default)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### getIdentityPublicKey()

> **getIdentityPublicKey**(): `Promise`\<[`PublicKey`](../type-aliases/PublicKey.md)\>

Get identity public key

#### Returns

`Promise`\<[`PublicKey`](../type-aliases/PublicKey.md)\>

***

### getSession()

> **getSession**(`remoteAddress`): `Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

Get the session record for a remote address.

Used by SESAME to sync sessions after PreKeyMessage decryption.
Per SESAME specification, after the responder decrypts a PreKeyMessage,
the session must sync from KeyStorage to DeviceRecord.

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

The session record, or null if no session exists

***

### initialize()

> **initialize**(`identityTypes?`): `Promise`\<`void`\>

Initialize identity keys on first launch

#### Parameters

##### identityTypes?

readonly [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)[]

Identity types to generate keys for (defaults to ['aci', 'pni'])

#### Returns

`Promise`\<`void`\>

***

### rotateEcSignedPreKey()

> **rotateEcSignedPreKey**(`userId`): `Promise`\<`void`\>

Rotate EC signed prekey (on the configured refresh interval, 2 days by default)

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`void`\>

***

### rotateKyberPreKey()

> **rotateKyberPreKey**(`userId`): `Promise`\<`void`\>

Rotate Kyber prekey (post-quantum security, same interval as the signed prekey)

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`void`\>

***

### setLocalIdentity()

> **setLocalIdentity**(`userId`, `deviceId`): `void`

Set local user and device identity.

Call this before any session operations (encrypt/decrypt).
generatePreKeyBundle normally calls it. Callers can also call it directly
when keys already exist and do not need regeneration.

#### Parameters

##### userId

`string`

User ID for this client

##### deviceId

`number`

Device ID (1 for primary, 2-5 for linked devices)

#### Returns

`void`

***

### startSession()

> **startSession**(`remoteAddress`, `prekeyBundle`, `recipientIdentityType?`): `Promise`\<`void`\>

Start a new session with a remote party

#### Parameters

##### remoteAddress

[`ProtocolAddress`](ProtocolAddress.md)

Remote party's protocol address (userId:deviceId)

##### prekeyBundle

[`RelayPreKeyBundle`](RelayPreKeyBundle.md)

Remote user's prekey bundle

##### recipientIdentityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`void`\>
