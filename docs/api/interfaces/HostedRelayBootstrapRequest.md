[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayBootstrapRequest

# Interface: HostedRelayBootstrapRequest

Request passed to a hosted Relay bootstrap transport.

## Properties

### assertion

> `readonly` **assertion**: `string`

***

### assertionPurpose

> `readonly` **assertionPurpose**: [`IdentityAssertionPurpose`](../type-aliases/IdentityAssertionPurpose.md)

***

### deviceAuthentication

> `readonly` **deviceAuthentication**: [`HostedRelayDeviceAuthentication`](HostedRelayDeviceAuthentication.md)

***

### operationId

> `readonly` **operationId**: `string`

Stable for exact retries and changes when the public registration material changes.

***

### publishableKey

> `readonly` **publishableKey**: `string`

***

### registrationId

> `readonly` **registrationId**: `number`

***

### registrationPreKeys

> `readonly` **registrationPreKeys**: [`HostedRelayRegistrationPreKeys`](HostedRelayRegistrationPreKeys.md)

***

### signalIdentity

> `readonly` **signalIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)
