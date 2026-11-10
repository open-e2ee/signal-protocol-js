[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayManagedDeviceLinkResult

# Interface: HostedSignalProtocolRelayManagedDeviceLinkResult

Canonical identity and authenticated Relay returned by hosted bootstrap.

SDK 14 also accepts the deprecated `signalProtocolRelayScopeId` and
`signalProtocolRelay` names. When an adapter sets both names of a member,
two different values fail with `SignalProtocolRelayNameConflictError`.
SDK 15.0.0 removes the deprecated names.

## Extends

- [`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md)

## Properties

### accountPreserved

> `readonly` **accountPreserved**: `true`

***

### canonicalAccountId

> `readonly` **canonicalAccountId**: `string`

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`canonicalAccountId`](HostedSignalProtocolRelayBootstrapResult.md#canonicalaccountid)

***

### deviceId

> `readonly` **deviceId**: `number`

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`deviceId`](HostedSignalProtocolRelayBootstrapResult.md#deviceid)

***

### protocolStateCopied

> `readonly` **protocolStateCopied**: `false`

***

### relay

> `readonly` **relay**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`relay`](HostedSignalProtocolRelayBootstrapResult.md#relay)

***

### relayScopeId

> `readonly` **relayScopeId**: `Uint8Array`

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`relayScopeId`](HostedSignalProtocolRelayBootstrapResult.md#relayscopeid)

***

### ~~signalProtocolRelay?~~

> `readonly` `optional` **signalProtocolRelay?**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

#### Deprecated

Use `relay`. SDK 15.0.0 removes this name.

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`signalProtocolRelay`](HostedSignalProtocolRelayBootstrapResult.md#signalprotocolrelay)

***

### ~~signalProtocolRelayScopeId?~~

> `readonly` `optional` **signalProtocolRelayScopeId?**: `Uint8Array`\<`ArrayBufferLike`\>

#### Deprecated

Use `relayScopeId`. SDK 15.0.0 removes this name.

#### Inherited from

[`HostedSignalProtocolRelayBootstrapResult`](HostedSignalProtocolRelayBootstrapResult.md).[`signalProtocolRelayScopeId`](HostedSignalProtocolRelayBootstrapResult.md#signalprotocolrelayscopeid)
