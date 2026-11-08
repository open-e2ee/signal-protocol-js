[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayBootstrapResult

# Interface: HostedSignalProtocolRelayBootstrapResult

Canonical identity and authenticated Relay returned by hosted bootstrap.

SDK 14 makes each new member optional and requires its deprecated earlier
name. When an adapter sets both names, the SDK reads the new member, and
two different values fail with `SignalProtocolRelayNameConflictError`.
SDK 15.0.0 requires the new members.

## Extended by

- [`HostedSignalProtocolRelayManagedDeviceLinkResult`](HostedSignalProtocolRelayManagedDeviceLinkResult.md)

## Properties

### canonicalAccountId

> `readonly` **canonicalAccountId**: `string`

***

### deviceId

> `readonly` **deviceId**: `number`

***

### ~~relay~~

> `readonly` **relay**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

#### Deprecated

Use `signalProtocolRelay`. SDK 15.0.0 requires `signalProtocolRelay` and removes this name.

***

### ~~relayScopeId~~

> `readonly` **relayScopeId**: `Uint8Array`

#### Deprecated

Use `signalProtocolRelayScopeId`. SDK 15.0.0 requires `signalProtocolRelayScopeId` and removes this name.

***

### signalProtocolRelay?

> `readonly` `optional` **signalProtocolRelay?**: [`SignalProtocolRelayServer`](SignalProtocolRelayServer.md)

***

### signalProtocolRelayScopeId?

> `readonly` `optional` **signalProtocolRelayScopeId?**: `Uint8Array`\<`ArrayBufferLike`\>
