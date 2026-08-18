[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / prepareMediaAttachmentUpload

# Function: prepareMediaAttachmentUpload()

> **prepareMediaAttachmentUpload**(`data`, `options`): `Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>

Encrypt and upload media bytes, returning a SDK attachment pointer.

The client computes the encrypted object digest and object ID once. Upload
retries request fresh presigned URLs for that same key. This handles expired
upload URLs without changing the pointer metadata that the client later
encrypts into the Signal Protocol message.

## Parameters

### data

`Uint8Array`

### options

[`PrepareMediaAttachmentUploadOptions`](../interfaces/PrepareMediaAttachmentUploadOptions.md)

## Returns

`Promise`\<[`MediaAttachmentPointer`](../interfaces/MediaAttachmentPointer.md)\>
