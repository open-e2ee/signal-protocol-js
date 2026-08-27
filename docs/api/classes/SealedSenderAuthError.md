[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SealedSenderAuthError

# Class: SealedSenderAuthError

Error thrown when sealed sender (anonymous delivery) authentication fails.

The server rejected the unidentified access key, for one of these reasons:
- The access key does not match the recipient's stored key
- The recipient's account was not found
- The recipient disabled unrestricted unidentified access

This error triggers automatic fallback to identified sender delivery.

## Example

```typescript
try {
  await relay.sendMultiRecipientUnidentified(message, accessKey, timestamp);
} catch (error) {
  if (isSealedSenderAuthError(error)) {
    // Fall back to identified delivery
    await relay.send(envelope);
  }
}
```

## Extends

- [`EncryptionError`](EncryptionError.md)

## Constructors

### Constructor

> **new SealedSenderAuthError**(`cause?`): `SealedSenderAuthError`

#### Parameters

##### cause?

`Error`

#### Returns

`SealedSenderAuthError`

#### Overrides

[`EncryptionError`](EncryptionError.md).[`constructor`](EncryptionError.md#constructor)

## Properties

### code

> **code**: [`EncryptionErrorCode`](../enumerations/EncryptionErrorCode.md)

#### Inherited from

[`EncryptionError`](EncryptionError.md).[`code`](EncryptionError.md#code)

***

### context?

> `optional` **context?**: [`EncryptionErrorContext`](../interfaces/EncryptionErrorContext.md)

#### Inherited from

[`EncryptionError`](EncryptionError.md).[`context`](EncryptionError.md#context)

## Accessors

### address

#### Get Signature

> **get** **address**(): [`ProtocolAddress`](../interfaces/ProtocolAddress.md) \| `undefined`

Get the protocol address from context if available

##### Returns

[`ProtocolAddress`](../interfaces/ProtocolAddress.md) \| `undefined`

#### Inherited from

[`EncryptionError`](EncryptionError.md).[`address`](EncryptionError.md#address)

***

### operation

#### Get Signature

> **get** **operation**(): `string` \| `undefined`

Get the operation from context if available

##### Returns

`string` \| `undefined`

#### Inherited from

[`EncryptionError`](EncryptionError.md).[`operation`](EncryptionError.md#operation)

***

### originalError

#### Get Signature

> **get** **originalError**(): `Error` \| `undefined`

Get the underlying error from context if available

##### Returns

`Error` \| `undefined`

#### Inherited from

[`EncryptionError`](EncryptionError.md).[`originalError`](EncryptionError.md#originalerror)
