[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayManagedDeviceLinkResult

# Interface: HostedRelayManagedDeviceLinkResult

Canonical identity and authenticated Relay returned by hosted bootstrap.

## Extends

- [`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md)

## Properties

### accountPreserved

> `readonly` **accountPreserved**: `true`

***

### canonicalAccountId

> `readonly` **canonicalAccountId**: `string`

#### Inherited from

[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md).[`canonicalAccountId`](HostedRelayBootstrapResult.md#canonicalaccountid)

***

### deviceId

> `readonly` **deviceId**: `number`

#### Inherited from

[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md).[`deviceId`](HostedRelayBootstrapResult.md#deviceid)

***

### protocolStateCopied

> `readonly` **protocolStateCopied**: `false`

***

### relay

> `readonly` **relay**: [`ISignalProtocolRelayServer`](ISignalProtocolRelayServer.md)

#### Inherited from

[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md).[`relay`](HostedRelayBootstrapResult.md#relay)

***

### relayScopeId

> `readonly` **relayScopeId**: `Uint8Array`

#### Inherited from

[`HostedRelayBootstrapResult`](HostedRelayBootstrapResult.md).[`relayScopeId`](HostedRelayBootstrapResult.md#relayscopeid)
