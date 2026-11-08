[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayIdentityMigrationRequest

# Interface: HostedSignalProtocolRelayIdentityMigrationRequest

## Properties

### action

> `readonly` **action**: [`HostedSignalProtocolRelayIdentityMigrationAction`](../type-aliases/HostedSignalProtocolRelayIdentityMigrationAction.md)

***

### authorization

> `readonly` **authorization**: \{ `deviceAuthentication`: [`HostedSignalProtocolRelayDeviceAuthentication`](HostedSignalProtocolRelayDeviceAuthentication.md); `kind`: `"active-device"`; \} \| \{ `assertion`: `string`; `kind`: `"assertion"`; \}

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
