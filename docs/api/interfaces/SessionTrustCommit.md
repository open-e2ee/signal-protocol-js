[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionTrustCommit

# Interface: SessionTrustCommit

All durable trust/session effects of establishing or advancing a session.
Optional one-time-prekey identifiers are consumed in the same transaction
for responder-side PreKey decrypts. The local identity namespace remains
explicit even when no prekey is consumed so every commit is fully scoped.

## Properties

### address

> **address**: [`ProtocolAddress`](ProtocolAddress.md)

***

### contactIdentity

> **contactIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Sender tuple to pin or match in the same durable commit.

***

### contactIdentityType

> **contactIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

***

### kemOneTimePreKeyId?

> `optional` **kemOneTimePreKeyId?**: `number`

***

### localIdentityType

> **localIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

Local identity namespace; also scopes any consumed recipient prekeys.

***

### oneTimePreKeyId?

> `optional` **oneTimePreKeyId?**: `number`

***

### record

> **record**: [`SessionRecord`](SessionRecord.md)
