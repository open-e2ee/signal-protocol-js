[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ServerDerivedKeyPair

# Class: ServerDerivedKeyPair

A specific secret key pair for issuing and verifying endorsements.

Derived from a [ServerRootKeyPair](ServerRootKeyPair.md) via
[ServerRootKeyPair.deriveKey](ServerRootKeyPair.md#derivekey).

## Constructors

### Constructor

> **new ServerDerivedKeyPair**(`skPrime`, `pub`): `ServerDerivedKeyPair`

#### Parameters

##### skPrime

`bigint`

##### pub

[`ServerDerivedPublicKey`](ServerDerivedPublicKey.md)

#### Returns

`ServerDerivedKeyPair`

## Properties

### public

> `readonly` **public**: [`ServerDerivedPublicKey`](ServerDerivedPublicKey.md)

***

### skPrime

> `readonly` **skPrime**: `bigint`

## Methods

### verify()

> **verify**(`point`, `token`): `void`

Verifies that a token is valid for `point` according to this key.

Throws [VerificationFailure](VerificationFailure.md) on mismatch.

#### Parameters

##### point

`RistrettoPoint`

##### token

`Uint8Array`

#### Returns

`void`
