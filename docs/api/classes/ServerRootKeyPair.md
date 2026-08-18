[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ServerRootKeyPair

# Class: ServerRootKeyPair

A server's root secret key for issuing and verifying endorsements.

Endorsements are not issued directly with this key. Instead, the server
derives a [ServerDerivedKeyPair](ServerDerivedKeyPair.md) for domain separation, rotation,
and additional authenticated info.

## Properties

### public

> `readonly` **public**: [`ServerRootPublicKey`](ServerRootPublicKey.md)

***

### sk

> `readonly` **sk**: `bigint`

## Methods

### deriveKey()

> **deriveKey**(`tagInfoSho`): [`ServerDerivedKeyPair`](ServerDerivedKeyPair.md)

Derives a specific key for issuing endorsements.

The `tagInfoSho` should have already absorbed domain separation and
any "public attributes" specific to the endorsements it issues.

#### Parameters

##### tagInfoSho

`ShoHmacSha256`

#### Returns

[`ServerDerivedKeyPair`](ServerDerivedKeyPair.md)

***

### publicKey()

> **publicKey**(): [`ServerRootPublicKey`](ServerRootPublicKey.md)

Returns the corresponding public key.

#### Returns

[`ServerRootPublicKey`](ServerRootPublicKey.md)

***

### fromRaw()

> `static` **fromRaw**(`sk`): `ServerRootKeyPair`

Construct from an existing secret scalar.

#### Parameters

##### sk

`bigint`

#### Returns

`ServerRootKeyPair`

***

### generate()

> `static` **generate**(`randomness`): `ServerRootKeyPair`

Derives a root key by hashing `randomness`.

#### Parameters

##### randomness

`Uint8Array`

#### Returns

`ServerRootKeyPair`
