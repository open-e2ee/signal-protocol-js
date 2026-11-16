[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / renameHostedSignalProtocolRelayDevice

# Function: renameHostedSignalProtocolRelayDevice()

> **renameHostedSignalProtocolRelayDevice**(`client`, `deviceId`, `name`): `Promise`\<`void`\>

Rename a device of the own account. The client encrypts `name` to the
account identity key, so each device of the account can read it, and the
Relay cannot. `listHostedSignalProtocolRelayDevices` shows the new name.

Device 1 can rename each device from 1 to 5. A linked device can rename
only itself.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

### deviceId

`number`

### name

`string`

## Returns

`Promise`\<`void`\>

## Throws

RangeError for a device ID that is not an integer from 1 to 5, or
a name that is not 1 to 50 UTF-16 code units. The call does not truncate a
name, and then sends no request.

## Throws

HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY`
when a linked device renames another device, `DEVICE_NOT_FOUND` when the
slot holds no device, or `SIGNAL_RELAY_UNSUPPORTED`.
