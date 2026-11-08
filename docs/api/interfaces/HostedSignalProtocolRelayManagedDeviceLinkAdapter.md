[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayManagedDeviceLinkAdapter

# Interface: HostedSignalProtocolRelayManagedDeviceLinkAdapter

Transport boundary for canonical managed device linking.

## Extends

- [`HostedSignalProtocolRelayBootstrapAdapter`](HostedSignalProtocolRelayBootstrapAdapter.md)

## Methods

### bootstrap()

> **bootstrap**(`request`): `Promise`\<[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md)\>

#### Parameters

##### request

[`HostedSignalProtocolRelayBootstrapRequest`](HostedSignalProtocolRelayBootstrapRequest.md)

#### Returns

`Promise`\<[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md)\>

#### Inherited from

[`HostedSignalProtocolRelayBootstrapAdapter`](HostedSignalProtocolRelayBootstrapAdapter.md).[`bootstrap`](HostedSignalProtocolRelayBootstrapAdapter.md#bootstrap)

***

### linkDevice()

> **linkDevice**(`request`): `Promise`\<[`HostedSignalProtocolRelayManagedDeviceLinkResult`](HostedSignalProtocolRelayManagedDeviceLinkResult.md)\>

#### Parameters

##### request

[`HostedSignalProtocolRelayManagedDeviceLinkRequest`](HostedSignalProtocolRelayManagedDeviceLinkRequest.md)

#### Returns

`Promise`\<[`HostedSignalProtocolRelayManagedDeviceLinkResult`](HostedSignalProtocolRelayManagedDeviceLinkResult.md)\>
