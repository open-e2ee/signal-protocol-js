[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RemoteObjectDownloadRequest

# Type Alias: RemoteObjectDownloadRequest

> **RemoteObjectDownloadRequest** = `object`

Request for a short-lived, direct object download operation.

## Properties

### objectId

> **objectId**: `string`

Opaque identifier from an encrypted attachment pointer.

***

### readCapability?

> `optional` **readCapability?**: `string`

Read authority carried inside the encrypted pointer, never in a URL.
