[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolRelayProtocolError

# Class: SignalProtocolRelayProtocolError

A Relay accepted a declared post without the `deviceSetChecked` mark. The
send is delivered and its result does not change, because a second post
could deliver the message twice. The client reports the error once for the
send through `onSignalProtocolRelayProtocolError`. A sync payload of a method such as
`syncReadToLinkedDevices` has no send ID, so its error has no
`clientMessageId`.

## Extends

- `Error`

## Constructors

### Constructor

> **new SignalProtocolRelayProtocolError**(`code`, `clientMessageId`, `route`): `SignalProtocolRelayProtocolError`

#### Parameters

##### code

`"DEVICE_SET_UNCHECKED"`

##### clientMessageId

`string` \| `undefined`

##### route

[`SignalProtocolRelayProtocolRoute`](../type-aliases/SignalProtocolRelayProtocolRoute.md)

#### Returns

`SignalProtocolRelayProtocolError`

#### Overrides

`Error.constructor`

## Properties

### clientMessageId

> `readonly` **clientMessageId**: `string` \| `undefined`

***

### code

> `readonly` **code**: `"DEVICE_SET_UNCHECKED"`

***

### name

> `readonly` **name**: `"RelayProtocolError"` = `'RelayProtocolError'`

#### Overrides

`Error.name`

***

### route

> `readonly` **route**: [`SignalProtocolRelayProtocolRoute`](../type-aliases/SignalProtocolRelayProtocolRoute.md)
