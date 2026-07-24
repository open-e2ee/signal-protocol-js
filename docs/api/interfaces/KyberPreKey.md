[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KyberPreKey

# Interface: KyberPreKey

ML-KEM-1024 prekey (historical public name, rotates weekly)

`KyberPreKey` is retained as an API identifier, but the bytes are standardized
ML-KEM-1024 with the profile's mandatory `0x0A` serialization.

## Properties

### keyId

> **keyId**: `number`

***

### privateKey

> **privateKey**: [`PrivateKey`](../type-aliases/PrivateKey.md)

***

### publicKey

> **publicKey**: [`PublicKey`](../type-aliases/PublicKey.md)

***

### signature

> **signature**: [`Signature`](../type-aliases/Signature.md)

***

### timestamp

> **timestamp**: `number`
