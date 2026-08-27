[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayBootstrapAdapter

# Interface: HostedRelayBootstrapAdapter

SDK or integration-owned hosted Relay transport.

Certificate roots are pinned in this adapter, outside the bootstrap response.
A Relay response cannot select the root that validates its own certificates.

## Extended by

- [`HostedRelayManagedDeviceLinkAdapter`](HostedRelayManagedDeviceLinkAdapter.md)

## Properties

### certificateTrust

> `readonly` **certificateTrust**: `object`

#### environment

> `readonly` **environment**: `"development"` \| `"production"`

#### revokedIssuerKeyIds

> `readonly` **revokedIssuerKeyIds**: readonly `number`[]

#### trustRoots

> `readonly` **trustRoots**: readonly `Uint8Array`\<`ArrayBufferLike`\>[]

## Methods

### bootstrap()

> **bootstrap**(`request`): `Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>

#### Parameters

##### request

[`HostedRelayBootstrapRequest`](HostedRelayBootstrapRequest.md)

#### Returns

`Promise`\<[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)\>
