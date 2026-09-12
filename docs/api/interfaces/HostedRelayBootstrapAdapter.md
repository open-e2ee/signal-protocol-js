[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayBootstrapAdapter

# Interface: HostedRelayBootstrapAdapter

SDK or integration-owned hosted Relay transport.

Managed Relay certificate roots are compiled into the SDK and selected by the
exact connection origin. The adapter cannot supply or replace hosted trust.

OpenE2EE has no customers. This is a clean prelaunch contract replacement.
Do not restore a certificateTrust compatibility property: accepting caller
trust would weaken the managed trust boundary. Self-hosted trust stays in its
separate explicit configuration.

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
