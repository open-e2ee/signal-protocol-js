[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedRelayPresence

# ~~Variable: hostedRelayPresence~~

> `const` **hostedRelayPresence**: (`client`) => [`HostedSignalProtocolRelayPresence`](../interfaces/HostedSignalProtocolRelayPresence.md) = `hostedSignalProtocolRelayPresence`

The presence of a hosted client with a mailbox subscription. Every request
goes over the socket, so start the subscription first. Each client has one
presence object, and its watches share one presence watch and one poll.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

## Returns

[`HostedSignalProtocolRelayPresence`](../interfaces/HostedSignalProtocolRelayPresence.md)

## Deprecated

Use `hostedSignalProtocolRelayPresence`. SDK 15.0.0 removes this name.
