[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / signMlKem1024PreKey

# Function: signMlKem1024PreKey()

> **signMlKem1024PreKey**(`identityKeyPair`, `keyId`, `serializedPublicKey`): `Promise`\<[`Signature`](../../../type-aliases/Signature.md)\>

Sign the canonical tagged ML-KEM-1024 prekey in its full identity context.

## Parameters

### identityKeyPair

[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)

### keyId

`number`

### serializedPublicKey

`Uint8Array`

## Returns

`Promise`\<[`Signature`](../../../type-aliases/Signature.md)\>
