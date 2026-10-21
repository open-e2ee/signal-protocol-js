[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceSetReconciliationError

# Class: DeviceSetReconciliationError

A declared send that ended without the acceptance of every device. The
devices in `acceptedDevices` stay accepted. The outbox keeps the send as
terminal, and the SDK does not post it again. A call of `send()` with the
same `clientMessageId` starts a new run at 0 restarts.

`isOutgoingMessageError` is true for this error.

## Extends

- `Error`

## Constructors

### Constructor

> **new DeviceSetReconciliationError**(`unresolved`, `devices`, `clientMessageId`): `DeviceSetReconciliationError`

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
