[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayDeviceUnknownError

# Class: HostedRelayDeviceUnknownError

The Relay has no device for the stored session, so the session cannot get
a device token. The message is the Relay's own message. It also names the
case where the account itself does not exist.

The SDK does not retry the request and does not register again. To keep
this device, call `createHostedSignalProtocolClient` with the
`assertionPurpose` `reregister` after the user confirms it.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayDeviceUnknownError**(`status`, `message`): `HostedRelayDeviceUnknownError`

#### Parameters

##### status

`number`

##### message

`string`

#### Returns

`HostedRelayDeviceUnknownError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `"NOT_FOUND"` = `"NOT_FOUND"`

***

### retryable

> `readonly` **retryable**: `false` = `false`

Always false: the same request fails again.

***

### status

> `readonly` **status**: `number`

The HTTP status of the refusal, 404 from a current Relay.
