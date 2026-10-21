[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / linkHostedRelayDevice

# Function: linkHostedRelayDevice()

> **linkHostedRelayDevice**(`options`): `Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

Bind a linked-device store to the Relay-authoritative account.

The linked store must already contain the account identity. The application
puts it there by device transfer or by a channel that the application owns.

The call reads both stores in the calling process. It signs the link
challenge with the device-authentication private key from
`activeDeviceStorage` and with the one from the linked store. Thus the
process that calls it must hold the active device's store. The adapter gets
the public identity, fresh linked-device prekey material, and two challenge
signers. It gets no private key.

## Parameters

### options

[`HostedRelayManagedDeviceLinkOptions`](../interfaces/HostedRelayManagedDeviceLinkOptions.md)

## Returns

`Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>
