[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayIdentityMigrationOptions

# Interface: HostedSignalProtocolRelayIdentityMigrationOptions

## Properties

### action

> `readonly` **action**: [`HostedSignalProtocolRelayIdentityMigrationAction`](../type-aliases/HostedSignalProtocolRelayIdentityMigrationAction.md)

***

### adapter

> `readonly` **adapter**: [`HostedSignalProtocolRelayIdentityMigrationAdapter`](HostedSignalProtocolRelayIdentityMigrationAdapter.md)

***

### authorization

> `readonly` **authorization**: \{ `kind`: `"active-device"`; `storage`: [`SignalProtocolLocalStore`](SignalProtocolLocalStore.md); \} \| \{ `kind`: `"assertion"`; `providerRole`: [`IdentityAssertionProviderRole`](../type-aliases/IdentityAssertionProviderRole.md); \}

***

### getIdentityAssertion

> `readonly` **getIdentityAssertion**: [`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

***

### manifestVersion?

> `readonly` `optional` **manifestVersion?**: `number`

***

### onProgress?

> `readonly` `optional` **onProgress?**: [`HostedSignalProtocolRelayIdentityProgressCallback`](../type-aliases/HostedSignalProtocolRelayIdentityProgressCallback.md)

***

### operationId

> `readonly` **operationId**: `string`

***

### relayUrl?

> `readonly` `optional` **relayUrl?**: `string`

Public environment-scoped Signal Protocol Relay connection URL. Set this
member or the deprecated `signalProtocolRelayUrl`.

***

### ~~signalProtocolRelayUrl?~~

> `readonly` `optional` **signalProtocolRelayUrl?**: `string`

#### Deprecated

Use `relayUrl`. SDK 15.0.0 removes this name.
