[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProcessedReceive

# Interface: ProcessedReceive

Content that `processIncomingEnvelope` gives. The client keeps it until
the application calls `completeReceive` with its `messageId`, or until
it expires after 30 days on this device. A redelivery of the
envelope gives it again with the same `messageId`.

## Properties

### groupId?

> `optional` **groupId?**: `string`

The group of group content.

***

### kind

> **kind**: `"processed"`

***

### messageId

> **messageId**: `string`

The ID that `completeReceive` takes.

***

### plaintext

> **plaintext**: `string`

The content, as its sender gave it.
