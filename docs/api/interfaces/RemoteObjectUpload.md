[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectUpload

# Interface: RemoteObjectUpload

Short-lived credentials for a direct object upload.

## Properties

### expiresAt

> **expiresAt**: `number`

Unix timestamp in milliseconds when the upload operation expires.

***

### headers?

> `optional` **headers?**: `Record`\<`string`, `string`\>

Request headers that must accompany the upload.

***

### objectId

> **objectId**: `string`

Canonical opaque identifier assigned to the uploaded object.

***

### protocol?

> `optional` **protocol?**: `"put"` \| `"tus"`

Upload protocol. Direct PUT is used when omitted.

***

### uploadUrl

> **uploadUrl**: `string`

Short-lived upload URL issued by the application's storage broker.
