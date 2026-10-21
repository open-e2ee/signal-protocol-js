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

### receiveWork?

> `optional` **receiveWork?**: `ReceiveWorkRecord`

The receive record of the decrypted message. The store writes it in the
same transaction as the session state, so the ratchet step and the
record roll back together.

***

### record

> **record**: [`SessionRecord`](SessionRecord.md)

***

### senderKeyHandoffInvalidation?

> `optional` **senderKeyHandoffInvalidation?**: [`SenderKeyHandoffDevice`](SenderKeyHandoffDevice.md)

The device whose sender-key handoffs this commit invalidates. The store
deletes the rows of that device in every group in the same transaction.
The session layer sets it for an inbound PreKey session and for an
outbound bundle session that archives a current session.
