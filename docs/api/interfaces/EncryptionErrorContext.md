[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / EncryptionErrorContext

# Interface: EncryptionErrorContext

## Indexable

> \[`key`: `string`\]: `unknown`

Additional context-specific data

## Properties

### address?

> `optional` **address?**: [`ProtocolAddress`](ProtocolAddress.md)

The protocol address involved in the error (if applicable)

***

### identity?

> `optional` **identity?**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

***

### identityKey?

> `optional` **identityKey?**: [`PublicKey`](../type-aliases/PublicKey.md)

The identity key involved (for trust/verification errors)

***

### operation?

> `optional` **operation?**: `string`

The operation in progress when the error occurred

***

### originalError?

> `optional` **originalError?**: `Error`

The underlying cause of the error
