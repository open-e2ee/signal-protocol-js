[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayAccountDeletionOptions

# Interface: HostedSignalProtocolRelayAccountDeletionOptions

Options for the retained account store and Relay URL.

## Properties

### relayUrl

> `readonly` **relayUrl**: `string`

The public environment-scoped Signal Protocol Relay connection URL of the hosted client.
Another URL of the same environment, publishable key, and Relay scope finds the same intent.

***

### storage

> `readonly` **storage**: [`SignalProtocolLocalStore`](SignalProtocolLocalStore.md)

The same open encrypted store that the hosted client uses.
Keep this store after deletion to retain the status capability and receipt.
Stop the client before deletion. The caller owns the store and its closure.
