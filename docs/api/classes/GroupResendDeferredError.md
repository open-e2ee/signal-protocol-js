[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupResendDeferredError

# Class: GroupResendDeferredError

A group resend waits for the group state, because the membership checker
answered `unavailable`. The resend job stays pending and the retry
request stays unacknowledged, so a later run decides again. Nothing ends
the answer to the failed envelope.

## Extends

- `Error`

## Constructors

### Constructor

> **new GroupResendDeferredError**(`groupId`): `GroupResendDeferredError`

#### Parameters

##### groupId

`string`

#### Returns

`GroupResendDeferredError`

#### Overrides

`Error.constructor`

## Properties

### groupId

> `readonly` **groupId**: `string`

***

### name

> `readonly` **name**: `"GroupResendDeferredError"` = `'GroupResendDeferredError'`

#### Overrides

`Error.name`
