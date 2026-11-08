[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayHttpError

# Class: HostedSignalProtocolRelayHttpError

The Signal Protocol Relay refused an HTTP request.

`status` is the HTTP status. `code`, `message`, and `retryable` come from
the Relay's error body. `code` is `UNKNOWN` when the body has none. The SDK
also throws this error with the Relay's status and code when it finds the
refusal before it sends the request.

A custom `HostedSignalProtocolRelayManagedDeviceLinkAdapter` throws this error when the
Relay refuses the link, with the Relay's `code` and `retryable`.
`linkHostedSignalProtocolRelayDevice` rolls the link back only for this error, with
`retryable` false and the code `KEY_PROOF_INVALID` or `CONFLICT`. It keeps
the link state for every other error.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedSignalProtocolRelayHttpError**(`status`, `code`, `message`, `options?`): `HostedSignalProtocolRelayHttpError`

`retryable` is false when `options` does not give it.

#### Parameters

##### status

`number`

##### code

`string`

##### message

`string`

##### options?

###### data?

`Readonly`\<`Record`\<`string`, `unknown`\>\>

###### retryable?

`boolean`

#### Returns

`HostedSignalProtocolRelayHttpError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `string`

The Relay's error code, for example `KEY_PROOF_INVALID`.

***

### data?

> `readonly` `optional` **data?**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

More values of the refusal. A refused declared post keeps the Relay's `details` here.

***

### retryable

> `readonly` **retryable**: `boolean`

The Relay's own hint that the same operation can be sent again. On an
error that `send()` throws before its posting deadline, the SDK sets
`retryable` to true and keeps this hint in `signalProtocolRelayRetryable`.

***

### status

> `readonly` **status**: `number`

The HTTP status of the response.
