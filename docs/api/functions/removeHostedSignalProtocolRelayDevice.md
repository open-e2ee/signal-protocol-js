[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / removeHostedSignalProtocolRelayDevice

# Function: removeHostedSignalProtocolRelayDevice()

> **removeHostedSignalProtocolRelayDevice**(`client`, `deviceId`): `Promise`\<`void`\>

Remove a device from the own account. The primary device can remove each
other device, and each device can remove itself. A removed client stops
with `HostedSignalProtocolRelayDeviceRevokedError`.

A device ID that holds no device resolves, because the account is then in
the requested state.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

### deviceId

`number`

## Returns

`Promise`\<`void`\>

## Throws

RangeError for device 1 or an ID that is not an integer. The call
then sends no request.

## Throws

HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY` or
`SIGNAL_RELAY_UNSUPPORTED`.
