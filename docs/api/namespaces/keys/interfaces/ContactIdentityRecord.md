[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / ContactIdentityRecord

# Interface: ContactIdentityRecord

Authoritative persisted trust record. Commitments are deliberately absent.

## Properties

### firstSeenAt

> `readonly` **firstSeenAt**: `number`

***

### identity

> `readonly` **identity**: [`CompositeIdentityV1`](CompositeIdentityV1.md)

***

### lastSeenAt

> `readonly` **lastSeenAt**: `number`

***

### retiredIdentities

> `readonly` **retiredIdentities**: readonly [`CompositeIdentityV1`](CompositeIdentityV1.md)[]

Canonical tuples retained solely for rollback detection.

***

### revision

> `readonly` **revision**: `number`

***

### trustState

> `readonly` **trustState**: [`IdentityTrustState`](../type-aliases/IdentityTrustState.md)

***

### verifiedAt?

> `readonly` `optional` **verifiedAt?**: `number`
