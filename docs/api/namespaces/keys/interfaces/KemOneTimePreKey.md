[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / KemOneTimePreKey

# Interface: KemOneTimePreKey

KEM one-time prekey (consumed on use, post-quantum)

Per PQXDH spec Section 3.2, the identity key signs these one-time pqkem prekeys
that provide per-session post-quantum forward secrecy.
Server prefers these over the last-resort KEM prekey.

## Properties

### keyId

> **keyId**: `number`

***

### privateKey

> **privateKey**: [`PrivateKey`](../../../type-aliases/PrivateKey.md)

***

### publicKey

> **publicKey**: [`PublicKey`](../../../type-aliases/PublicKey.md)

***

### signature

> **signature**: [`Signature`](../../../type-aliases/Signature.md)

***

### timestamp

> **timestamp**: `number`
