[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayIdentityMigrationOptions

# Interface: HostedRelayIdentityMigrationOptions

## Properties

### action

> `readonly` **action**: [`HostedRelayIdentityMigrationAction`](../type-aliases/HostedRelayIdentityMigrationAction.md)

***

### adapter

> `readonly` **adapter**: [`HostedRelayIdentityMigrationAdapter`](HostedRelayIdentityMigrationAdapter.md)

***

### authorization

> `readonly` **authorization**: \{ `kind`: `"active-device"`; `storage`: [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md); \} \| \{ `kind`: `"assertion"`; `providerRole`: [`IdentityAssertionProviderRole`](../type-aliases/IdentityAssertionProviderRole.md); \}

***

### getIdentityAssertion

> `readonly` **getIdentityAssertion**: [`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

***

### manifestVersion?

> `readonly` `optional` **manifestVersion?**: `number`

***

### onProgress?

> `readonly` `optional` **onProgress?**: [`HostedRelayIdentityProgressCallback`](../type-aliases/HostedRelayIdentityProgressCallback.md)

***

### operationId

> `readonly` **operationId**: `string`

***

### relayUrl

> `readonly` **relayUrl**: `string`

Public environment-scoped Managed Relay connection URL.
