[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / PrepareMediaAttachmentUploadOptions

# Interface: PrepareMediaAttachmentUploadOptions

## Properties

### blurHash?

> `optional` **blurHash?**: `string`

***

### caption?

> `optional` **caption?**: `string`

***

### cdnNumber?

> `optional` **cdnNumber?**: `number`

***

### clientUuid?

> `optional` **clientUuid?**: `string`

***

### contentType?

> `optional` **contentType?**: `string`

***

### durationMs?

> `optional` **durationMs?**: `number`

***

### fileName?

> `optional` **fileName?**: `string`

***

### flags?

> `optional` **flags?**: `number`

***

### height?

> `optional` **height?**: `number`

***

### isViewOnce?

> `optional` **isViewOnce?**: `boolean`

***

### onCheckpoint?

> `optional` **onCheckpoint?**: [`MediaAttachmentCheckpointCallback`](../type-aliases/MediaAttachmentCheckpointCallback.md)

***

### onProgress?

> `optional` **onProgress?**: [`MediaAttachmentProgressCallback`](../type-aliases/MediaAttachmentProgressCallback.md)

***

### policy?

> `optional` **policy?**: [`MediaAttachmentPolicy`](MediaAttachmentPolicy.md)

***

### remoteObjectStore

> **remoteObjectStore**: [`SignalProtocolRemoteObjectStore`](../../../interfaces/SignalProtocolRemoteObjectStore.md)

***

### requestId?

> `optional` **requestId?**: `string`

Stable idempotency key for this logical upload.

Supply the same value when restarting an interrupted upload. A random
value is generated when omitted.

***

### resume?

> `optional` **resume?**: [`MediaAttachmentResumeState`](MediaAttachmentResumeState.md)

***

### retry?

> `optional` **retry?**: [`MediaAttachmentRetryOptions`](MediaAttachmentRetryOptions.md)

***

### signal?

> `optional` **signal?**: `AbortSignal`

***

### thumbnail?

> `optional` **thumbnail?**: `string`

***

### transfer?

> `optional` **transfer?**: [`MediaAttachmentTransfer`](MediaAttachmentTransfer.md)

***

### waveform?

> `optional` **waveform?**: `number`[]

***

### width?

> `optional` **width?**: `number`
