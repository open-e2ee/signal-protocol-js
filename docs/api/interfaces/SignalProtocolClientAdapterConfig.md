[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientAdapterConfig

# Interface: SignalProtocolClientAdapterConfig

Concrete infrastructure adapters for a Signal Protocol client.

Apps normally provide local storage and a relay. A remote object store is
only needed for encrypted attachments.

## Properties

### protocolManager?

> `optional` **protocolManager?**: [`ISignalProtocolManager`](ISignalProtocolManager.md)

Advanced protocol manager override for tests and specialized integrations.

***

### relay?

> `optional` **relay?**: [`ISignalProtocolRelayServer`](ISignalProtocolRelayServer.md)

Optional relay for server sync, prekeys, fanout, and subscriptions.

***

### remoteObjectStore?

> `optional` **remoteObjectStore?**: [`SignalProtocolRemoteObjectStore`](SignalProtocolRemoteObjectStore.md)

Optional brokered remote object store for encrypted attachments.

***

### storage

> **storage**: [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md)

Required local protocol store for the current runtime.
