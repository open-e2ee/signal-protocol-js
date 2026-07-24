[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / prepareMediaAttachmentUpload

# Function: prepareMediaAttachmentUpload()

> **prepareMediaAttachmentUpload**(`data`, `options`): `Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>

Encrypt and upload media bytes, returning a SDK attachment pointer.

The encrypted object digest and object ID are computed once. Upload
retries request fresh presigned URLs for that same key, which handles expired
upload URLs without changing the pointer metadata that will be encrypted into
the Signal message.

## Parameters

### data

`Uint8Array`

### options

[`PrepareMediaAttachmentUploadOptions`](../interfaces/PrepareMediaAttachmentUploadOptions.md)

## Returns

`Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>
