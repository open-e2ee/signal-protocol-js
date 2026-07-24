[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectDownload

# Interface: RemoteObjectDownload

Short-lived credentials for a direct object download.

## Properties

### downloadUrl

> **downloadUrl**: `string`

Short-lived download URL issued by the application's storage broker.

***

### expiresAt

> **expiresAt**: `number`

Unix timestamp in milliseconds when the download operation expires.

***

### headers?

> `optional` **headers?**: `Record`\<`string`, `string`\>

Request headers that must accompany the download.
