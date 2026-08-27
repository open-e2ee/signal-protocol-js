[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / createHostedSignalProtocolClient

# Function: createHostedSignalProtocolClient()

> **createHostedSignalProtocolClient**(`options`): `Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>

Create a hosted Relay client without accepting a caller-supplied account or device ID.

The Relay verifies the assertion and device proof, then returns the canonical
account, registered device, scope, and authenticated transport used by the client.

## Parameters

### options

[`HostedSignalProtocolClientOptions`](../interfaces/HostedSignalProtocolClientOptions.md)

## Returns

`Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>
