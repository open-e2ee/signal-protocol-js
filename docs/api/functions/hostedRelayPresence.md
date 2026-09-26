[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedRelayPresence

# Function: hostedRelayPresence()

> **hostedRelayPresence**(`client`): [`HostedRelayPresence`](../interfaces/HostedRelayPresence.md)

The presence of a hosted client with a mailbox subscription. Every request
goes over the socket, so start the subscription first. Each client has one
presence object, and its watches share one presence watch and one poll.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

## Returns

[`HostedRelayPresence`](../interfaces/HostedRelayPresence.md)
