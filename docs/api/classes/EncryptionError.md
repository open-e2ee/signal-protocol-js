[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / EncryptionError

# Class: EncryptionError

Base encryption error class.

Enhanced with context support for better error handling and debugging.
Provides error patterns.

## Example

```typescript
throw new EncryptionError(
  'Session not found',
  EncryptionErrorCode.SESSION_NOT_FOUND,
  { address, operation: 'encryptMessage' }
);
```

## Extends

- `Error`

## Extended by

- [`SealedSenderAuthError`](SealedSenderAuthError.md)

## Constructors

### Constructor

> **new EncryptionError**(`message`, `code`, `context?`): `EncryptionError`

#### Parameters

##### message

`string`

##### code

[`EncryptionErrorCode`](../enumerations/EncryptionErrorCode.md)

##### context?

[`EncryptionErrorContext`](../interfaces/EncryptionErrorContext.md)

#### Returns

`EncryptionError`

#### Overrides

`Error.constructor`

## Properties

### code

> **code**: [`EncryptionErrorCode`](../enumerations/EncryptionErrorCode.md)

***

### context?

> `optional` **context?**: [`EncryptionErrorContext`](../interfaces/EncryptionErrorContext.md)

## Accessors

### address

#### Get Signature

> **get** **address**(): [`ProtocolAddress`](../interfaces/ProtocolAddress.md) \| `undefined`

Get the protocol address from context if available

##### Returns

[`ProtocolAddress`](../interfaces/ProtocolAddress.md) \| `undefined`

***

### operation

#### Get Signature

> **get** **operation**(): `string` \| `undefined`

Get the operation from context if available

##### Returns

`string` \| `undefined`

***

### originalError

#### Get Signature

> **get** **originalError**(): `Error` \| `undefined`

Get the underlying error from context if available

##### Returns

`Error` \| `undefined`
