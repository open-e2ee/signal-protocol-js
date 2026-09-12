[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayIdentityMigrationRequest

# Interface: HostedRelayIdentityMigrationRequest

## Properties

### action

> `readonly` **action**: [`HostedRelayIdentityMigrationAction`](../type-aliases/HostedRelayIdentityMigrationAction.md)

***

### authorization

> `readonly` **authorization**: \{ `deviceAuthentication`: [`HostedRelayDeviceAuthentication`](HostedRelayDeviceAuthentication.md); `kind`: `"active-device"`; \} \| \{ `assertion`: `string`; `kind`: `"assertion"`; \}

***

### manifestVersion?

> `readonly` `optional` **manifestVersion?**: `number`

***

### operationId

> `readonly` **operationId**: `string`

***

### protocolEndpoint

> `readonly` **protocolEndpoint**: `string`

***

### publishableKey

> `readonly` **publishableKey**: `string`

***

### targetAssertion?

> `readonly` `optional` **targetAssertion?**: `string`
