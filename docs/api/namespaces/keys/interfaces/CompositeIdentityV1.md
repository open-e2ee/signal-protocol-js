[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / CompositeIdentityV1

# Interface: CompositeIdentityV1

Canonical identity profile selected by this SDK.

## Properties

### ed25519PublicKey

> `readonly` **ed25519PublicKey**: [`PublicKey`](../../../type-aliases/PublicKey.md)

Standard Ed25519 public key used to authenticate prekeys.

***

### version

> `readonly` **version**: `1`

Canonical tuple version. Encoded as `0x01`.

***

### x25519PublicKey

> `readonly` **x25519PublicKey**: [`PublicKey`](../../../type-aliases/PublicKey.md)

Standard X25519 public key used by X3DH/PQXDH.
