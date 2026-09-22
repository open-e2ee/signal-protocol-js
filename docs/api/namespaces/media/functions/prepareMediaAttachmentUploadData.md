[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / prepareMediaAttachmentUploadData

# Function: prepareMediaAttachmentUploadData()

> **prepareMediaAttachmentUploadData**(`data`, `options?`): `Promise`\<[`PreparedMediaAttachmentUpload`](../../../interfaces/PreparedMediaAttachmentUpload.md)\>

Prepare exact encrypted bytes without contacting the remote object store.

## Parameters

### data

`Uint8Array`

### options?

`Omit`\<[`PrepareMediaAttachmentUploadOptions`](../interfaces/PrepareMediaAttachmentUploadOptions.md), `"remoteObjectStore"`\> = `{}`

## Returns

`Promise`\<[`PreparedMediaAttachmentUpload`](../../../interfaces/PreparedMediaAttachmentUpload.md)\>
