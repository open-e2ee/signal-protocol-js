[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreparedMediaAttachmentUpload

# Interface: PreparedMediaAttachmentUpload

Private device-local state. Never put this record in logs or Relay requests.

## Properties

### ciphertext

> `readonly` **ciphertext**: `Uint8Array`

***

### plaintextDigest

> `readonly` **plaintextDigest**: `string`

***

### pointer

> `readonly` **pointer**: `Omit`\<[`MediaAttachmentPointer`](../namespaces/media/interfaces/MediaAttachmentPointer.md), `"storageId"` \| `"uploadTimestamp"`\>

***

### preparedAt

> `readonly` **preparedAt**: `number`

Immutable Unix time in milliseconds when preparation starts.

***

### requestId

> `readonly` **requestId**: `string`
