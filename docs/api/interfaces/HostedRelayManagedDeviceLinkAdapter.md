[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayManagedDeviceLinkAdapter

# Interface: HostedRelayManagedDeviceLinkAdapter

Transport boundary for canonical managed device linking.

## Extends

- [`HostedRelayBootstrapAdapter`](HostedRelayBootstrapAdapter.md)

## Methods

### bootstrap()

> **bootstrap**(`request`): `Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>

#### Parameters

##### request

[`HostedRelayBootstrapRequest`](HostedRelayBootstrapRequest.md)

#### Returns

`Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>

#### Inherited from

[`HostedRelayBootstrapAdapter`](HostedRelayBootstrapAdapter.md).[`bootstrap`](HostedRelayBootstrapAdapter.md#bootstrap)

***

### linkDevice()

> **linkDevice**(`request`): `Promise`\<[`HostedRelayManagedDeviceLinkResult`](HostedRelayManagedDeviceLinkResult.md)\>

#### Parameters

##### request

[`HostedRelayManagedDeviceLinkRequest`](HostedRelayManagedDeviceLinkRequest.md)

#### Returns

`Promise`\<[`HostedRelayManagedDeviceLinkResult`](HostedRelayManagedDeviceLinkResult.md)\>
