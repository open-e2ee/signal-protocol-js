[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionTrustCommit

# Interface: SessionTrustCommit

All durable trust/session effects of establishing or advancing a session.
The same transaction consumes optional one-time-prekey identifiers
for responder-side PreKey decrypts. The local identity namespace remains
explicit even when the transaction consumes no prekey, so every commit
is fully scoped.

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

### kyberPreKeyUse?

> `optional` **kyberPreKeyUse?**: `object`

Reusable Kyber-prekey replay evidence committed with the accepted session.

#### baseKeyBytes

> **baseKeyBytes**: `Uint8Array`

#### kyberPreKeyId

> **kyberPreKeyId**: `number`

#### kyberPreKeyInstanceId

> **kyberPreKeyInstanceId**: `string`

#### signedPreKeyId

> **signedPreKeyId**: `number`

***

### localIdentityType

> **localIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

Local identity namespace. It also scopes any consumed recipient prekeys.

***

### oneTimePreKeyId?

> `optional` **oneTimePreKeyId?**: `number`

***

### receivedContent?

> `optional` **receivedContent?**: `ReceivedContent`

***

### record

> **record**: [`SessionRecord`](SessionRecord.md)
