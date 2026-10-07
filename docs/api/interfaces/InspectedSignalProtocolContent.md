[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / InspectedSignalProtocolContent

# Interface: InspectedSignalProtocolContent

## Properties

### conversationId?

> `optional` **conversationId?**: `string`

***

### nullMessage

> **nullMessage**: `boolean`

True for a null message. A sender answers a retry request with one
when it no longer has the plaintext. A null message carries no
content. The client consumes a null message when the content adapter
reports `nullMessage: true`, and never gives it to the application.
A custom adapter must report it for its own null encoding.

***

### profileKey?

> `optional` **profileKey?**: `string`

The sender's profile key, from `dataMessage.profileKey`, as standard base64.

***

### profileKeyUpdate?

> `optional` **profileKeyUpdate?**: `boolean`

True for a DataMessage with the Signal `PROFILE_KEY_UPDATE` flag.

***

### receipt

> **receipt**: [`ParsedReceiptContent`](ParsedReceiptContent.md) \| `null`

***

### senderKeyDistribution?

> `optional` **senderKeyDistribution?**: `ParsedSenderKeyDistribution`

***

### shouldSendDeliveryReceipt

> **shouldSendDeliveryReceipt**: `boolean`

***

### sync

> **sync**: `ParsedSyncContent` \| `null`

***

### timestamp?

> `optional` **timestamp?**: `number`

***

### typing

> **typing**: [`ParsedTypingContent`](ParsedTypingContent.md) \| `null`
