[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / MediaAttachmentTransferCheckpoint

# Interface: MediaAttachmentTransferCheckpoint

## Properties

### attachmentId?

> `optional` **attachmentId?**: `string`

***

### attempt?

> `optional` **attempt?**: `number`

***

### bytesTransferred?

> `optional` **bytesTransferred?**: `number`

***

### operation

> **operation**: `"upload"` \| `"download"`

***

### phase

> **phase**: `"complete"` \| `"transfer"` \| `"retry"` \| `"request-url"`

***

### requestId?

> `optional` **requestId?**: `string`

Stable idempotency key for one logical upload.

***

### resumeToken?

> `optional` **resumeToken?**: `string`

***

### storageId?

> `optional` **storageId?**: `string`

***

### totalBytes?

> `optional` **totalBytes?**: `number`

***

### updatedAt

> **updatedAt**: `number`
