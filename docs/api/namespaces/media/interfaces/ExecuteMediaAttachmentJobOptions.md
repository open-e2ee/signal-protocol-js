[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / ExecuteMediaAttachmentJobOptions

# Interface: ExecuteMediaAttachmentJobOptions

## Properties

### deleteLocalAttachment?

> `optional` **deleteLocalAttachment?**: (`job`) => `Promise`\<`void`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

#### Returns

`Promise`\<`void`\>

***

### loadAttachmentPointer?

> `optional` **loadAttachmentPointer?**: (`job`) => `Promise`\<[`CreateMediaAttachmentPointerInput`](../type-aliases/CreateMediaAttachmentPointerInput.md) \| `null`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

#### Returns

`Promise`\<[`CreateMediaAttachmentPointerInput`](../type-aliases/CreateMediaAttachmentPointerInput.md) \| `null`\>

***

### loadUploadData?

> `optional` **loadUploadData?**: (`job`) => `Promise`\<[`MediaAttachmentUploadJobData`](MediaAttachmentUploadJobData.md) \| `null`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

#### Returns

`Promise`\<[`MediaAttachmentUploadJobData`](MediaAttachmentUploadJobData.md) \| `null`\>

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

### retry?

> `optional` **retry?**: [`MediaAttachmentRetryOptions`](MediaAttachmentRetryOptions.md)

***

### saveDownloadedAttachment?

> `optional` **saveDownloadedAttachment?**: (`job`, `attachment`) => `Promise`\<`void`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

##### attachment

[`ResolvedMediaAttachment`](ResolvedMediaAttachment.md)

#### Returns

`Promise`\<`void`\>

***

### saveUploadedAttachment?

> `optional` **saveUploadedAttachment?**: (`job`, `attachment`) => `Promise`\<`void`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

##### attachment

[`MediaAttachmentPointer`](MediaAttachmentPointer.md)

#### Returns

`Promise`\<`void`\>

***

### signal?

> `optional` **signal?**: `AbortSignal`

***

### syncDelete?

> `optional` **syncDelete?**: (`job`, `deleteSync`) => `Promise`\<`void`\>

#### Parameters

##### job

[`MediaAttachmentBackgroundJob`](MediaAttachmentBackgroundJob.md)

##### deleteSync

[`MediaAttachmentDeleteSyncInput`](../../../interfaces/MediaAttachmentDeleteSyncInput.md)

#### Returns

`Promise`\<`void`\>

***

### transfer?

> `optional` **transfer?**: [`MediaAttachmentTransfer`](MediaAttachmentTransfer.md)
