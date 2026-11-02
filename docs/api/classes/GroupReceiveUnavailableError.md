[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupReceiveUnavailableError

# Class: GroupReceiveUnavailableError

The client cannot decide on group content yet, because its group state
is not current. The content is committed in a receive record under
`messageId`, and the receive queue decides it when the group state
updates. No client method throws it: `processIncomingEnvelope` gives a
`pending` outcome for it. A redelivery of the envelope finds the record
and spends no second ratchet step. `messageId` is absent only on an
error that no receive record backs.

## Extends

- `Error`

## Constructors

### Constructor

> **new GroupReceiveUnavailableError**(`reason`, `retryAfterMs`, `messageId?`): `GroupReceiveUnavailableError`

#### Parameters

##### reason

[`GroupReceiveUnavailability`](../type-aliases/GroupReceiveUnavailability.md)

##### retryAfterMs

`number`

##### messageId?

`string`

#### Returns

`GroupReceiveUnavailableError`

#### Overrides

`Error.constructor`

## Properties

### messageId?

> `readonly` `optional` **messageId?**: `string`

***

### name

> `readonly` **name**: `"GroupReceiveUnavailableError"` = `'GroupReceiveUnavailableError'`

#### Overrides

`Error.name`

***

### reason

> `readonly` **reason**: [`GroupReceiveUnavailability`](../type-aliases/GroupReceiveUnavailability.md)

***

### retryAfterMs

> `readonly` **retryAfterMs**: `number`
