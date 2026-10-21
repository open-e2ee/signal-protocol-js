[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayProtocolError

# Class: RelayProtocolError

A Relay accepted a declared post without the `deviceSetChecked` mark. The
send is delivered and its result does not change, because a second post
could deliver the message twice. The client reports the error once for the
send through `onRelayProtocolError`. A sync payload of a method such as
`syncReadToLinkedDevices` has no send ID, so its error has no
`clientMessageId`.

## Extends

- `Error`

## Constructors

### Constructor

> **new RelayProtocolError**(`code`, `clientMessageId`, `route`): `RelayProtocolError`

#### Parameters

##### code

`"DEVICE_SET_UNCHECKED"`

##### clientMessageId

`string` \| `undefined`

##### route

[`RelayProtocolRoute`](../type-aliases/RelayProtocolRoute.md)

#### Returns

`RelayProtocolError`

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

> `readonly` **route**: [`RelayProtocolRoute`](../type-aliases/RelayProtocolRoute.md)
