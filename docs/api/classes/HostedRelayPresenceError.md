[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayPresenceError

# Class: HostedRelayPresenceError

A presence request that the Relay refused or that got no answer.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayPresenceError**(`code`, `message`, `retryable`): `HostedRelayPresenceError`

#### Parameters

##### code

[`HostedRelayPresenceErrorCode`](../type-aliases/HostedRelayPresenceErrorCode.md)

##### message

`string`

##### retryable

`boolean`

#### Returns

`HostedRelayPresenceError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`HostedRelayPresenceErrorCode`](../type-aliases/HostedRelayPresenceErrorCode.md)

***

### retryable

> `readonly` **retryable**: `boolean`

True when the same request can be sent again later.
