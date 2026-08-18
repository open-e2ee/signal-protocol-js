[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IKyberLastResortPreKeyStore

# Interface: IKyberLastResortPreKeyStore

Kyber Last-Resort PreKey store interface (post-quantum security).

Manages the ML-KEM-1024 (Kyber) last-resort prekey for post-quantum forward secrecy.
This is a reusable fallback key (like EC signed prekeys) that rotates on the
configured refresh interval (2 days by default).

Naming convention matches EC prekeys:
- `IEcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
- `IEcSignedPreKeyStore` → reusable EC prekey (`ecSignedPreKeys`)
- `IKemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`) - FUTURE
- `IKyberLastResortPreKeyStore` → reusable KEM prekey (`kemLastResortPreKeys`)

## See

https://signal.org/docs/specifications/pqxdh/

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

### getKyberPreKey()

> **getKyberPreKey**(`identityType?`): `Promise`\<[`KyberPreKey`](KyberPreKey.md) \| `null`\>

Retrieve Kyber prekey.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`KyberPreKey`](KyberPreKey.md) \| `null`\>

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
