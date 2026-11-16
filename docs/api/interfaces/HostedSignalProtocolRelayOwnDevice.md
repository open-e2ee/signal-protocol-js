[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayOwnDevice

# Interface: HostedSignalProtocolRelayOwnDevice

A device of the own account.

## Properties

### deviceId

> `readonly` **deviceId**: `number`

***

### isCurrent

> `readonly` **isCurrent**: `boolean`

True for the device of this client.

***

### isPrimary

> `readonly` **isPrimary**: `boolean`

True for device 1, the device that approves links.

***

### linkedAt?

> `readonly` `optional` **linkedAt?**: `Date`

The time of the link, for a device that a link made.

***

### name?

> `readonly` `optional` **name?**: `string`

The device name, when the device has one that this client can read.
