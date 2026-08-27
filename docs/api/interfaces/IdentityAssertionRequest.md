[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IdentityAssertionRequest

# Interface: IdentityAssertionRequest

Additional context for a purpose-aware assertion request.

## Properties

### assurance?

> `readonly` `optional` **assurance?**: [`IdentityAssertionAssurance`](../type-aliases/IdentityAssertionAssurance.md)

***

### migration?

> `readonly` `optional` **migration?**: `object`

#### action

> `readonly` **action**: [`HostedRelayIdentityMigrationAction`](../type-aliases/HostedRelayIdentityMigrationAction.md)

#### providerRole

> `readonly` **providerRole**: [`IdentityAssertionProviderRole`](../type-aliases/IdentityAssertionProviderRole.md)

***

### purpose

> `readonly` **purpose**: [`IdentityAssertionPurpose`](../type-aliases/IdentityAssertionPurpose.md)
