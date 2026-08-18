[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DecryptedEnvelope

# Interface: DecryptedEnvelope

## Properties

### content

> **content**: `string`

Decrypted plaintext content (typically JSON)

***

### conversationId

> **conversationId**: `string`

Conversation ID (groupId for groups, recipientId for 1:1)

***

### isGroup

> **isGroup**: `boolean`

Whether this is a group message

***

### messageId

> **messageId**: `string`

Unique message ID (from server or generated)

***

### messageType?

> `optional` **messageType?**: `string`

Message type hint (if available from envelope) - apps define their own type unions

***

### receivedAt

> **receivedAt**: `number`

When the device received the message locally

***

### senderDeviceId

> **senderDeviceId**: `number`

Sender's device ID

***

### senderId

> **senderId**: `string`

Sender's user ID

***

### serverTimestamp?

> `optional` **serverTimestamp?**: `number`

Relay server timestamp when available

***

### sessionId

> **sessionId**: `string`

Session ID used for decryption (userId.deviceId format)

***

### timestamp

> **timestamp**: `number`

Message timestamp (from sender)
