[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IEcOneTimePreKeyStore

# Interface: IEcOneTimePreKeyStore

EC one-time PreKey store with an SDK-oriented API.

Manages EC one-time prekeys for forward secrecy.
One-time prekeys are consumed after use and cannot be reused.

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

### getEcOneTimePreKeys()

> **getEcOneTimePreKeys**(`identityType?`): `Promise`\<[`EcOneTimePreKey`](EcOneTimePreKey.md)[]\>

Retrieve all EC one-time prekeys.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcOneTimePreKey`](EcOneTimePreKey.md)[]\>

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
