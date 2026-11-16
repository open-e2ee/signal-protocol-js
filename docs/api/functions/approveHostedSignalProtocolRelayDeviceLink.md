[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / approveHostedSignalProtocolRelayDeviceLink

# Function: approveHostedSignalProtocolRelayDeviceLink()

> **approveHostedSignalProtocolRelayDeviceLink**(`client`, `linkCode`, `options?`): `Promise`\<\{ `deviceId`: `number`; \}\>

Approve the device link of `linkCode` on the primary device. The client
sends the account identity, the groups, and `applicationData` to the new
device through the provisioning channel. The Relay cannot read them. The
new device joins with `joinHostedSignalProtocolRelayAccount`, and sets its
own name with `hosted.deviceName` of that call.

The call resolves only after the new device has linked: the Relay has a
device from the redeem of the link token that this call issued. The call
reads the link status with a wait of 500 ms that doubles to 5 s. It
resolves with the device ID of the linked device. The Relay keeps the
`linked` status of the token after a later removal of the device, so a
resolved call does not prove that the device is still on the account. To
see the current devices, use `listHostedSignalProtocolRelayDevices` or
`hosted.onOwnDevicesChanged`.

## Parameters

### client

[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

### linkCode

`string`

### options?

[`HostedSignalProtocolRelayDeviceLinkApprovalOptions`](../interfaces/HostedSignalProtocolRelayDeviceLinkApprovalOptions.md) = `{}`

## Returns

`Promise`\<\{ `deviceId`: `number`; \}\>

## Throws

RangeError when `applicationData` is above 16,384 bytes. The call
then sends no request.

## Throws

HostedSignalProtocolRelayDeviceProvisioningError for a refusal of
the link (wire contract section 11.1): `LINK_CODE_EXPIRED` when the link
code expires before the delivery, or the link token expires before the new
device links, and `CANCELLED` when `signal` fires.
