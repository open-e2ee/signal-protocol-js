[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / MediaAttachmentTransfer

# Interface: MediaAttachmentTransfer

## Methods

### download()?

> `optional` **download**(`url`, `options?`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### Parameters

##### url

`string`

##### options?

[`MediaAttachmentTransferOptions`](MediaAttachmentTransferOptions.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### upload()?

> `optional` **upload**(`url`, `data`, `options?`): `Promise`\<[`MediaAttachmentUploadResponse`](MediaAttachmentUploadResponse.md)\>

#### Parameters

##### url

`string`

##### data

`Uint8Array`

##### options?

[`MediaAttachmentTransferOptions`](MediaAttachmentTransferOptions.md)

#### Returns

`Promise`\<[`MediaAttachmentUploadResponse`](MediaAttachmentUploadResponse.md)\>
