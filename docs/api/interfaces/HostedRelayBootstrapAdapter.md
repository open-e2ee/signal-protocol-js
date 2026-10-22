[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayBootstrapAdapter

# Interface: HostedRelayBootstrapAdapter

SDK or integration-owned Signal Protocol Relay transport.

Signal Protocol Relay certificate roots are compiled into the SDK and selected by the
exact connection origin. The adapter cannot supply or replace hosted trust.

The adapter has no `certificateTrust` property. Trust that the caller
supplies would weaken the managed trust boundary. Self-hosted trust stays in
its separate explicit configuration.

## Extended by

- [`HostedRelayManagedDeviceLinkAdapter`](HostedRelayManagedDeviceLinkAdapter.md)

## Methods

### bootstrap()

> **bootstrap**(`request`): `Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>

#### Parameters

##### request

[`HostedRelayBootstrapRequest`](HostedRelayBootstrapRequest.md)

#### Returns

`Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>
