[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / InspectedSignalProtocolContent

# Interface: InspectedSignalProtocolContent

## Properties

### conversationId?

> `optional` **conversationId?**: `string`

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
