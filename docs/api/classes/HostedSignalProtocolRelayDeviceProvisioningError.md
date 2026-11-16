[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayDeviceProvisioningError

# Class: HostedSignalProtocolRelayDeviceProvisioningError

A device link stopped. The same input gives the same refusal, so
`retryable` is always false.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedSignalProtocolRelayDeviceProvisioningError**(`code`, `message`, `options?`): `HostedSignalProtocolRelayDeviceProvisioningError`

#### Parameters

##### code

[`HostedSignalProtocolRelayDeviceProvisioningErrorCode`](../type-aliases/HostedSignalProtocolRelayDeviceProvisioningErrorCode.md)

##### message

`string`

##### options?

###### cause?

`unknown`

#### Returns

`HostedSignalProtocolRelayDeviceProvisioningError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`HostedSignalProtocolRelayDeviceProvisioningErrorCode`](../type-aliases/HostedSignalProtocolRelayDeviceProvisioningErrorCode.md)

***

### retryable

> `readonly` **retryable**: `false`

Always false: the same input is refused again.
