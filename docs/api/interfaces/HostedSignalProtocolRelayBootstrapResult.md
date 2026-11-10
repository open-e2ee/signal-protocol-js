[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayBootstrapResult

# Interface: HostedSignalProtocolRelayBootstrapResult

Canonical identity and authenticated Relay returned by hosted bootstrap.

SDK 14 also accepts the deprecated `signalProtocolRelayScopeId` and
`signalProtocolRelay` names. When an adapter sets both names of a member,
two different values fail with `SignalProtocolRelayNameConflictError`.
SDK 15.0.0 removes the deprecated names.

## Extended by

- [`HostedSignalProtocolRelayManagedDeviceLinkResult`](HostedSignalProtocolRelayManagedDeviceLinkResult.md)

## Properties

### canonicalAccountId

> `readonly` **canonicalAccountId**: `string`

***

### deviceId

> `readonly` **deviceId**: `number`

***

### relay

> `readonly` **relay**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

***

### relayScopeId

> `readonly` **relayScopeId**: `Uint8Array`

***

### ~~signalProtocolRelay?~~

> `readonly` `optional` **signalProtocolRelay?**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

#### Deprecated

Use `relay`. SDK 15.0.0 removes this name.

***

### ~~signalProtocolRelayScopeId?~~

> `readonly` `optional` **signalProtocolRelayScopeId?**: `Uint8Array`\<`ArrayBufferLike`\>

#### Deprecated

Use `relayScopeId`. SDK 15.0.0 removes this name.
