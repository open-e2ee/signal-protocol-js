[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupReceiveRefusedError

# Class: GroupReceiveRefusedError

The client delivers no group content: its context is malformed or names
another group, the group is blocked, or the verified group state refuses
it. A resend of the content would be refused again, so the receive paths
ask for no resend.

## Extends

- `Error`

## Constructors

### Constructor

> **new GroupReceiveRefusedError**(`reason`): `GroupReceiveRefusedError`

#### Parameters

##### reason

[`GroupReceiveDenial`](../type-aliases/GroupReceiveDenial.md)

#### Returns

`GroupReceiveRefusedError`

#### Overrides

`Error.constructor`

## Properties

### name

> `readonly` **name**: `"GroupReceiveRefusedError"` = `'GroupReceiveRefusedError'`

#### Overrides

`Error.name`

***

### reason

> `readonly` **reason**: [`GroupReceiveDenial`](../type-aliases/GroupReceiveDenial.md)
