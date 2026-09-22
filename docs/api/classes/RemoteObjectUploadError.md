[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectUploadError

# Class: RemoteObjectUploadError

A broker refusal, distinct from a renewable transfer URL or uncertain network failure.

## Extends

- `Error`

## Constructors

### Constructor

> **new RemoteObjectUploadError**(`code`): `RemoteObjectUploadError`

#### Parameters

##### code

[`RemoteObjectUploadFailureCode`](../type-aliases/RemoteObjectUploadFailureCode.md)

#### Returns

`RemoteObjectUploadError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`RemoteObjectUploadFailureCode`](../type-aliases/RemoteObjectUploadFailureCode.md)
