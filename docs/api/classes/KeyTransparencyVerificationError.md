[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KeyTransparencyVerificationError

# Class: KeyTransparencyVerificationError

A key transparency check failed. `code` names the step that failed. The
message names the step and holds no key bytes and no account address.

## Extends

- `Error`

## Constructors

### Constructor

> **new KeyTransparencyVerificationError**(`code`, `message`): `KeyTransparencyVerificationError`

#### Parameters

##### code

[`KeyTransparencyFailureCode`](../type-aliases/KeyTransparencyFailureCode.md)

##### message

`string`

#### Returns

`KeyTransparencyVerificationError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`KeyTransparencyFailureCode`](../type-aliases/KeyTransparencyFailureCode.md)

***

### name

> `readonly` **name**: `"KeyTransparencyVerificationError"` = `'KeyTransparencyVerificationError'`

#### Overrides

`Error.name`
