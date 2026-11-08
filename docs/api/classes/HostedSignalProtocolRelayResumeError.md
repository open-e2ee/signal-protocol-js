[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayResumeError

# Class: HostedSignalProtocolRelayResumeError

A strict-resume refusal. An unresolved cleanup remains owned by this error.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedSignalProtocolRelayResumeError**(`code`, `phase`, `options?`): `HostedSignalProtocolRelayResumeError`

#### Parameters

##### code

[`HostedSignalProtocolRelayResumeErrorCode`](../type-aliases/HostedSignalProtocolRelayResumeErrorCode.md)

##### phase

[`HostedSignalProtocolRelayResumePhase`](../type-aliases/HostedSignalProtocolRelayResumePhase.md)

##### options?

`ErrorOptions`

#### Returns

`HostedSignalProtocolRelayResumeError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`HostedSignalProtocolRelayResumeErrorCode`](../type-aliases/HostedSignalProtocolRelayResumeErrorCode.md)

***

### phase

> `readonly` **phase**: [`HostedSignalProtocolRelayResumePhase`](../type-aliases/HostedSignalProtocolRelayResumePhase.md)

## Accessors

### cleanupPending

#### Get Signature

> **get** **cleanupPending**(): `boolean`

True while this error still owns a client whose stop has not completed.

##### Returns

`boolean`

## Methods

### retryCleanup()

> **retryCleanup**(): `Promise`\<`void`\>

Retry only the held client's stop. Never retries resume or closes storage.

#### Returns

`Promise`\<`void`\>
