[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayOwnDevicesChangedCallback

# Type Alias: HostedSignalProtocolRelayOwnDevicesChangedCallback

> **HostedSignalProtocolRelayOwnDevicesChangedCallback** = (`change`) => `void`

Called when a read of the own device list finds a change. `added` holds
the new own devices other than this device. `removed` holds the own
devices that the account no longer lists.

## Parameters

### change

#### added

readonly `number`[]

#### removed

readonly `number`[]

## Returns

`void`
