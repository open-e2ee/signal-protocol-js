[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / verifyMlKem1024PreKey

# Function: verifyMlKem1024PreKey()

> **verifyMlKem1024PreKey**(`identity`, `keyId`, `serializedPublicKey`, `signature`): `Promise`\<`boolean`\>

Verify the canonical tagged ML-KEM-1024 prekey in its full identity context.

## Parameters

### identity

[`CompositeIdentityV1`](../interfaces/CompositeIdentityV1.md)

### keyId

`number`

### serializedPublicKey

`Uint8Array`\<`ArrayBufferLike`\> \| [`PublicKey`](../../../type-aliases/PublicKey.md)

### signature

[`Signature`](../../../type-aliases/Signature.md)

## Returns

`Promise`\<`boolean`\>
