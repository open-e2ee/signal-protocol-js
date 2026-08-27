[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / linkHostedRelayDevice

# Function: linkHostedRelayDevice()

> **linkHostedRelayDevice**(`options`): `Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>

Bind a provisioned linked-device store to the Relay-authoritative account.

The linked store must already contain the account identity delivered by the
SDK provisioning protocol. Only public identity and fresh linked-device
prekey material crosses this managed boundary.

## Parameters

### options

[`HostedRelayManagedDeviceLinkOptions`](../interfaces/HostedRelayManagedDeviceLinkOptions.md)

## Returns

`Promise`\<[`SignalProtocolClient`](../classes/SignalProtocolClient.md)\>
