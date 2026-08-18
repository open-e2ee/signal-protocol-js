[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectUploadRequest

# Type Alias: RemoteObjectUploadRequest

> **RemoteObjectUploadRequest** = `object`

Request for a short-lived, direct object upload operation.

`requestId` is an idempotency key for one logical upload. It is not an
object identifier or a provider key. An authenticated backend maps it to a
stable canonical object identifier and a private provider key.

## Properties

### contentLength

> **contentLength**: `number`

Exact encrypted object length in bytes.

***

### contentType

> **contentType**: `string`

MIME type of the encrypted bytes in the upload.

***

### requestId

> **requestId**: `string`

Stable idempotency key for retries of one logical upload.

The backend must scope this untrusted value to the authenticated principal
and return the same object reservation when the caller retries the request.
