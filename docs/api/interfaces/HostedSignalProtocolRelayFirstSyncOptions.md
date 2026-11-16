[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayFirstSyncOptions

# Interface: HostedSignalProtocolRelayFirstSyncOptions

## Properties

### signal?

> `readonly` `optional` **signal?**: `AbortSignal`

Stops the send. The call then rejects with `CANCELLED`. A signal that
fires after the Relay accepted the copy does not stop the delivery.
