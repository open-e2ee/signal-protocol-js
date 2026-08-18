[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ServerRootPublicKey

# Class: ServerRootPublicKey

The public counterpart of [ServerRootKeyPair](ServerRootKeyPair.md).

Verify issuance with a [ServerDerivedPublicKey](ServerDerivedPublicKey.md).

## Constructors

### Constructor

> **new ServerRootPublicKey**(`PK`): `ServerRootPublicKey`

#### Parameters

##### PK

`RistrettoPoint`

#### Returns

`ServerRootPublicKey`

## Properties

### PK

> `readonly` **PK**: `RistrettoPoint`

## Methods

### deriveKey()

> **deriveKey**(`tagInfoSho`): [`ServerDerivedPublicKey`](ServerDerivedPublicKey.md)

Derives a specific public key for endorsement verification.

The `tagInfoSho` must match what the server used in
[ServerRootKeyPair.deriveKey](ServerRootKeyPair.md#derivekey).

#### Parameters

##### tagInfoSho

`ShoHmacSha256`

#### Returns

[`ServerDerivedPublicKey`](ServerDerivedPublicKey.md)

***

### fromRaw()

> `static` **fromRaw**(`PK`): `ServerRootPublicKey`

Construct from an existing point (expected to be sk * G).

#### Parameters

##### PK

`RistrettoPoint`

#### Returns

`ServerRootPublicKey`
