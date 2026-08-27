[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayManagedDeviceLinkAdapter

# Interface: HostedRelayManagedDeviceLinkAdapter

Transport boundary for canonical managed device linking.

## Extends

- [`HostedRelayBootstrapAdapter`](HostedRelayBootstrapAdapter.md)

## Properties

### certificateTrust

> `readonly` **certificateTrust**: `object`

#### environment

> `readonly` **environment**: `"development"` \| `"production"`

#### revokedIssuerKeyIds

> `readonly` **revokedIssuerKeyIds**: readonly `number`[]

#### trustRoots

> `readonly` **trustRoots**: readonly `Uint8Array`\<`ArrayBufferLike`\>[]

#### Inherited from

[`HostedRelayBootstrapAdapter`](HostedRelayBootstrapAdapter.md).[`certificateTrust`](HostedRelayBootstrapAdapter.md#certificatetrust)

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
