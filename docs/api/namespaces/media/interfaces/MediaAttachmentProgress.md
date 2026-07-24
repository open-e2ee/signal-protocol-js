[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / MediaAttachmentProgress

# Interface: MediaAttachmentProgress

## Properties

### attempt?

> `optional` **attempt?**: `number`

***

### bytesTransferred?

> `optional` **bytesTransferred?**: `number`

***

### operation

> **operation**: `"upload"` \| `"download"` \| `"delete"`

***

### phase

> **phase**: `"complete"` \| `"transfer"` \| `"retry"` \| `"delete"` \| `"encrypt"` \| `"request-url"` \| `"verify"` \| `"decrypt"`

***

### reason?

> `optional` **reason?**: `"expired-url"` \| `"invalid-resume"` \| `"retryable-status"` \| `"transient-failure"`

***

### requestId?

> `optional` **requestId?**: `string`

Stable idempotency key for one logical upload.

***

### retryInMs?

> `optional` **retryInMs?**: `number`

***

### status?

> `optional` **status?**: `number`

***

### storageId?

> `optional` **storageId?**: `string`

***

### totalBytes?

> `optional` **totalBytes?**: `number`
