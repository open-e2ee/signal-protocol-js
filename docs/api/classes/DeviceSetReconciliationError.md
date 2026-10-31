[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceSetReconciliationError

# Class: DeviceSetReconciliationError

A declared send that ended without the acceptance of every device. The
devices in `acceptedDevices` stay accepted. After a recipient-phase end,
the outbox keeps the send as terminal with its `outcome`, and the SDK does
not post it again. A later `send()` with the same `clientMessageId` throws
the stored-end class of its outcome, `SendAcceptanceUnknownError` or
`SendNeverAcceptedByRelayError`, and posts nothing.

`isOutgoingMessageError` is true for this error.

## Extends

- `Error`

## Constructors

### Constructor

> **new DeviceSetReconciliationError**(`unresolved`, `devices`, `clientMessageId`, `outcome?`): `DeviceSetReconciliationError`

#### Parameters

##### unresolved

[`DeviceSetUnresolved`](../interfaces/DeviceSetUnresolved.md)

##### devices

###### acceptedDevices

readonly [`DeviceSetDevice`](../interfaces/DeviceSetDevice.md)[]

###### unresolvedDevices

readonly [`DeviceSetDevice`](../interfaces/DeviceSetDevice.md)[]

##### clientMessageId

`string`

##### outcome?

`"failed"` \| `"acceptance-unknown"`

#### Returns

`DeviceSetReconciliationError`

#### Overrides

`Error.constructor`

## Properties

### acceptedDevices

> `readonly` **acceptedDevices**: readonly [`DeviceSetDevice`](../interfaces/DeviceSetDevice.md)[]

***

### clientMessageId

> `readonly` **clientMessageId**: `string`

***

### lastRefusal

> `readonly` **lastRefusal**: [`DeviceSetLastRefusal`](../interfaces/DeviceSetLastRefusal.md) \| `undefined`

***

### name

> `readonly` **name**: `"DeviceSetReconciliationError"` = `'DeviceSetReconciliationError'`

#### Overrides

`Error.name`

***

### outcome

> `readonly` **outcome**: `"failed"` \| `"acceptance-unknown"` \| `undefined`

The stored end of the send after a recipient-phase end: `failed` or
`acceptance-unknown`. With `acceptance-unknown`, the message might have
arrived. Undefined after a sync-phase end, which keeps the result of
the send.

***

### phase

> `readonly` **phase**: [`DeviceSetPhase`](../type-aliases/DeviceSetPhase.md)

***

### reason

> `readonly` **reason**: [`DeviceSetUnresolvedReason`](../type-aliases/DeviceSetUnresolvedReason.md)

***

### restarts

> `readonly` **restarts**: `number`

***

### unresolvedDevices

> `readonly` **unresolvedDevices**: readonly [`DeviceSetDevice`](../interfaces/DeviceSetDevice.md)[]
