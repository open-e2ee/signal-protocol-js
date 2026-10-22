[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayDeviceLinkError

# Class: HostedRelayDeviceLinkError

The linked store already holds state that a new device link would replace.

The link refuses a linked store in two cases, and it writes nothing before
either refusal:

- The linked group store lists a group that this link did not write. The
  link copies the group master keys of the active device into an empty
  group store, and a rollback removes each copied group.
- The store holds a device-authentication key for this Relay connection,
  with no registration of this link. The Relay refuses a key that a device
  already holds, and a new registration ID with that key could replace the
  registration ID of a live device.

Use a new, empty store for the linked device. The SDK does not retry the
link.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayDeviceLinkError**(`message`): `HostedRelayDeviceLinkError`

#### Parameters

##### message

`string`

#### Returns

`HostedRelayDeviceLinkError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `"DEVICE_LINK_STORE_NOT_EMPTY"` = `"DEVICE_LINK_STORE_NOT_EMPTY"`

***

### retryable

> `readonly` **retryable**: `false` = `false`

Always false: the same store is refused again.
