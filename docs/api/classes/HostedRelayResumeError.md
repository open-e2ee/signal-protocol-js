[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayResumeError

# Class: HostedRelayResumeError

A strict-resume refusal. An unresolved cleanup remains owned by this error.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayResumeError**(`code`, `phase`, `options?`): `HostedRelayResumeError`

#### Parameters

##### code

[`HostedRelayResumeErrorCode`](../type-aliases/HostedRelayResumeErrorCode.md)

##### phase

[`HostedRelayResumePhase`](../type-aliases/HostedRelayResumePhase.md)

##### options?

`ErrorOptions`

#### Returns

`HostedRelayResumeError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`HostedRelayResumeErrorCode`](../type-aliases/HostedRelayResumeErrorCode.md)

***

### phase

> `readonly` **phase**: [`HostedRelayResumePhase`](../type-aliases/HostedRelayResumePhase.md)

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
