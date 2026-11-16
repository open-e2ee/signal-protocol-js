[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IdentityChangedEvent

# Interface: IdentityChangedEvent

An identity change of a contact that the client detected.

The client detects a change when its trust gate refuses an identity that
differs from the pinned identity of the user. The refusal stays: the send or
the decrypt still fails with `UntrustedIdentityError`. To trust the new
identity, call `acceptIdentityRotation(userId, currentIdentity, identityType)`.

## Properties

### currentIdentity

> `readonly` **currentIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

The identity that the trust gate refused.

***

### deviceId

> `readonly` **deviceId**: `number`

The device of the user that presented `currentIdentity`.

***

### direction

> `readonly` **direction**: [`TrustDirection`](../enumerations/TrustDirection.md)

The path that detected the change: `sending` or `receiving`.

***

### identityType

> `readonly` **identityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

The identity type of the pinned identity, `'aci'` or `'pni'`.

***

### previousIdentity

> `readonly` **previousIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

The pinned identity of the user.

***

### status

> `readonly` **status**: `"CHANGED"` \| `"ROLLBACK"`

`'CHANGED'` for an identity that the client has not pinned before.
`'ROLLBACK'` for an identity that the client pinned before and retired
when it accepted a later identity.

***

### trustState

> `readonly` **trustState**: [`IdentityTrustState`](../namespaces/keys/type-aliases/IdentityTrustState.md)

The trust state of the pinned identity.

***

### userId

> `readonly` **userId**: `string`

The user whose identity changed.
