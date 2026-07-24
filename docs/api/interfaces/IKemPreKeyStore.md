[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IKemPreKeyStore

# Interface: IKemPreKeyStore

Kyber One-Time PreKey store interface (post-quantum security).

Manages one-time ML-KEM-1024 (Kyber) prekeys for per-session post-quantum forward secrecy.
One-time KEM prekeys are consumed after use and provide additional security layer
beyond the last-resort Kyber prekey.

Naming convention matches EC prekeys:
- `IEcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
- `IKemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`)

## See

https://signal.org/docs/specifications/pqxdh/ Section 3.2

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

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
