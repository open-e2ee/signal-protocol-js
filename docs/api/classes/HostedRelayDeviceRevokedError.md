[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayDeviceRevokedError

# Class: HostedRelayDeviceRevokedError

An account recovery revoked this device. The Relay refuses its key on the
device token request and on a registration, so both fail the same way. The
SDK does not retry the request.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayDeviceRevokedError**(`status`, `message?`): `HostedRelayDeviceRevokedError`

#### Parameters

##### status

`number`

##### message?

`string` = `DEVICE_REVOKED_MESSAGE`

#### Returns

`HostedRelayDeviceRevokedError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `"DEVICE_REVOKED"` = `"DEVICE_REVOKED"`

***

### retryable

> `readonly` **retryable**: `false` = `false`

Always false: the Relay refuses these keys for good.

***

### status

> `readonly` **status**: `number`

The HTTP status of the refusal, 403 from a current Relay.
