[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayBootstrapRequest

# Interface: HostedSignalProtocolRelayBootstrapRequest

Request passed to a Signal Protocol Relay bootstrap transport.

## Properties

### assertion

> `readonly` **assertion**: `string`

***

### assertionPurpose

> `readonly` **assertionPurpose**: [`IdentityAssertionPurpose`](../type-aliases/IdentityAssertionPurpose.md)

***

### deviceAuthentication

> `readonly` **deviceAuthentication**: [`HostedSignalProtocolRelayDeviceAuthentication`](HostedSignalProtocolRelayDeviceAuthentication.md)

***

### operationId

> `readonly` **operationId**: `string`

Stable for exact retries and changes when the public registration material changes.

***

### protocolEndpoint

> `readonly` **protocolEndpoint**: `string`

***

### publishableKey

> `readonly` **publishableKey**: `string`

***

### registrationId

> `readonly` **registrationId**: `number`

***

### registrationPreKeys

> `readonly` **registrationPreKeys**: [`HostedSignalProtocolRelayRegistrationPreKeys`](HostedSignalProtocolRelayRegistrationPreKeys.md)

***

### signalIdentity

> `readonly` **signalIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)
