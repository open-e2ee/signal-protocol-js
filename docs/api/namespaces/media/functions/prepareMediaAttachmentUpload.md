[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / prepareMediaAttachmentUpload

# Function: prepareMediaAttachmentUpload()

> **prepareMediaAttachmentUpload**(`data`, `options`): `Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>

Encrypt and upload media bytes within one invocation.
For restart recovery, persist prepareMediaAttachmentUploadData before calling uploadPreparedMediaAttachment.

## Parameters

### data

`Uint8Array`

### options

[`PrepareMediaAttachmentUploadOptions`](../interfaces/PrepareMediaAttachmentUploadOptions.md)

## Returns

`Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>
