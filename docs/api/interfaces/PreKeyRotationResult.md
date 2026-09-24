[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreKeyRotationResult

# Interface: PreKeyRotationResult

Result of one prekey rotation.

Each boolean is true when the rotation published that kind of key for any
identity type. `errors` holds one message per identity type whose rotation
failed; the other identity types still complete.

## Properties

### errors

> **errors**: `string`[]

One message per failed identity type (non-fatal)

***

### kyberRotated

> **kyberRotated**: `boolean`

Whether the rotation published a new KEM last-resort prekey

***

### oneTimeReplenished

> **oneTimeReplenished**: `boolean`

Whether the rotation published a fresh one-time prekey batch

***

### signedRotated

> **signedRotated**: `boolean`

Whether the rotation published a new EC signed prekey
