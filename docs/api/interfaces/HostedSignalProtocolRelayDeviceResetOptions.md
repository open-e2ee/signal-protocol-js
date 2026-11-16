[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayDeviceResetOptions

# Interface: HostedSignalProtocolRelayDeviceResetOptions

The options of `resetRemovedHostedSignalProtocolRelayDevice`.

## Properties

### adapters

> `readonly` **adapters**: `object`

#### storage

> `readonly` **storage**: [`SignalProtocolLocalStore`](SignalProtocolLocalStore.md)

The store of the removed device. Stop each client of this store before
the reset, and do not use the store until the reset settles.

***

### groups?

> `readonly` `optional` **groups?**: `HostedGroupOptions`

The group options of the removed client. Give them when the client had
a `groups.store` of its own, so that the reset also deletes each group
that the store lists. The SDK group store is in `storage`.

***

### hosted

> `readonly` **hosted**: `object`

#### relayUrl

> `readonly` **relayUrl**: `string`

The public environment-scoped Signal Protocol Relay connection URL.
