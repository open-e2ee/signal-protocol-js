[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientMediaConfig

# Interface: SignalProtocolClientMediaConfig

## Properties

### baseRetryDelayMs?

> `optional` **baseRetryDelayMs?**: `number`

First retry delay for transient job failures.

#### Default

```ts
30000
```

***

### deleteLocalAttachment?

> `optional` **deleteLocalAttachment?**: (`input`) => `Promise`\<`void`\>

Delete app-owned local cache state for a cleanup job.

#### Parameters

##### input

[`SignalProtocolClientDeleteLocalAttachmentInput`](SignalProtocolClientDeleteLocalAttachmentInput.md)

#### Returns

`Promise`\<`void`\>

***

### loadLocalAttachment?

> `optional` **loadLocalAttachment?**: (`input`) => `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| [`SignalProtocolClientLoadedLocalAttachment`](SignalProtocolClientLoadedLocalAttachment.md) \| `null`\>

Load app-owned local bytes for a queued upload.

The Signal Protocol package owns encryption and upload execution. The app owns draft
files, cache paths, and file permissions, so bytes enter the queue through
this callback instead of hidden package storage.

#### Parameters

##### input

[`SignalProtocolClientLoadLocalAttachmentInput`](SignalProtocolClientLoadLocalAttachmentInput.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| [`SignalProtocolClientLoadedLocalAttachment`](SignalProtocolClientLoadedLocalAttachment.md) \| `null`\>

***

### maxAttempts?

> `optional` **maxAttempts?**: `number`

Maximum attempts before the queue removes a failing job.

#### Default

```ts
5
```

***

### maxJobs?

> `optional` **maxJobs?**: `number`

Bound the queue kept in the Signal Protocol local store metadata.

#### Default

```ts
200
```

***

### maxRetryDelayMs?

> `optional` **maxRetryDelayMs?**: `number`

Maximum retry delay for transient job failures.

#### Default

```ts
3600000
```

***

### saveDownloadedAttachment?

> `optional` **saveDownloadedAttachment?**: (`input`) => `Promise`\<`void`\>

Persist plaintext bytes returned by a queued download.

#### Parameters

##### input

[`SignalProtocolClientSaveDownloadedAttachmentInput`](SignalProtocolClientSaveDownloadedAttachmentInput.md)

#### Returns

`Promise`\<`void`\>

***

### saveUploadedAttachment?

> `optional` **saveUploadedAttachment?**: (`input`) => `Promise`\<`void`\>

Persist the encrypted attachment pointer produced by a queued upload.

#### Parameters

##### input

[`SignalProtocolClientSaveUploadedAttachmentInput`](SignalProtocolClientSaveUploadedAttachmentInput.md)

#### Returns

`Promise`\<`void`\>

***

### syncDelete?

> `optional` **syncDelete?**: (`input`) => `Promise`\<`void`\>

Optional linked-device cleanup sync sender.

#### Parameters

##### input

[`SignalProtocolClientSyncDeleteInput`](SignalProtocolClientSyncDeleteInput.md)

#### Returns

`Promise`\<`void`\>
