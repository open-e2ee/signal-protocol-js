[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectUploadRequest

# Type Alias: RemoteObjectUploadRequest

> **RemoteObjectUploadRequest** = `object`

Request for a short-lived, direct object upload operation.

`requestId` and `preparedAt` identify one immutable preparation. Neither is an
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

### digest

> **digest**: `Uint8Array`

SHA-256 digest of the exact encrypted bytes.

***

### preparedAt

> **preparedAt**: `number`

Immutable preparation time in Unix milliseconds. Never refresh it for a retry.

***

### readCapabilityDigest?

> `optional` **readCapabilityDigest?**: `Uint8Array`

Optional broker read-capability commitment. Required by hosted Relay.

***

### requestId

> **requestId**: `string`

Stable nonce for retries of one logical upload.

The backend must scope this untrusted value to the authenticated principal
and preparation time. Exact retries return the same object reservation.
