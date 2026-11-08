[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayPresenceError

# Class: HostedSignalProtocolRelayPresenceError

A presence request that the Relay refused or that got no answer.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedSignalProtocolRelayPresenceError**(`code`, `message`, `retryable`): `HostedSignalProtocolRelayPresenceError`

#### Parameters

##### code

[`HostedSignalProtocolRelayPresenceErrorCode`](../type-aliases/HostedSignalProtocolRelayPresenceErrorCode.md)

##### message

`string`

##### retryable

`boolean`

#### Returns

`HostedSignalProtocolRelayPresenceError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`HostedSignalProtocolRelayPresenceErrorCode`](../type-aliases/HostedSignalProtocolRelayPresenceErrorCode.md)

***

### retryable

> `readonly` **retryable**: `boolean`

True when the same request can be sent again later.
