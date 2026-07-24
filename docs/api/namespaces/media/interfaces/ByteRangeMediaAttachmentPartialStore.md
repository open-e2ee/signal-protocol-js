[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / ByteRangeMediaAttachmentPartialStore

# Interface: ByteRangeMediaAttachmentPartialStore

## Methods

### clear()?

> `optional` **clear**(`resume`): `Promise`\<`void`\>

Remove a persisted ciphertext prefix. Implementations should make this
idempotent and non-throwing where possible because the transfer treats
cleanup as best-effort after stale prefixes, terminal failures, and
completed downloads.

#### Parameters

##### resume

[`MediaAttachmentResumeState`](MediaAttachmentResumeState.md)

#### Returns

`Promise`\<`void`\>

***

### load()

> **load**(`resume`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Load the ciphertext prefix for a non-zero download resume state.

#### Parameters

##### resume

[`MediaAttachmentResumeState`](MediaAttachmentResumeState.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

***

### save()

> **save**(`resume`, `bytes`): `Promise`\<`void`\>

Persist the ciphertext prefix that matches the supplied resume offset.

#### Parameters

##### resume

[`MediaAttachmentResumeState`](MediaAttachmentResumeState.md)

##### bytes

`Uint8Array`

#### Returns

`Promise`\<`void`\>
