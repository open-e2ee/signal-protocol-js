[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / UntrustedIdentityError

# Class: UntrustedIdentityError

Error thrown when an identity key is not trusted.

This is a security-critical error that requires user intervention.
The user must verify the safety number before continuing communication.

## Example

```typescript
throw new UntrustedIdentityError(address, identityKey);
```

## Extends

- [`EncryptionError`](EncryptionError.md)

## Constructors

### Constructor

> **new UntrustedIdentityError**(`address`, `identity`): `UntrustedIdentityError`

#### Parameters

##### address

[`ProtocolAddress`](../interfaces/ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

#### Returns

`UntrustedIdentityError`

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

***

### identity

> `readonly` **identity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

***

### untrustedAddress

> `readonly` **untrustedAddress**: [`ProtocolAddress`](../interfaces/ProtocolAddress.md)

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
