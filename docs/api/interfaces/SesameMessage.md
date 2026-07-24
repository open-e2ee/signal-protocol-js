[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SesameMessage

# Interface: SesameMessage

SESAME message structure for encrypted communication

## Properties

### ciphertext

> **ciphertext**: `Uint8Array`

Encrypted message ciphertext (from Double Ratchet)

***

### initHeader

> **initHeader**: `Uint8Array`\<`ArrayBufferLike`\> \| `null`

X3DH/PQXDH header data for initiating messages
Null for non-initiating messages

***

### isInitiating

> **isInitiating**: `boolean`

Whether this is an initiating message (contains X3DH/PQXDH header)

***

### recipientDeviceId

> **recipientDeviceId**: `number`

Recipient's device ID

***

### recipientUserId

> **recipientUserId**: `string`

Recipient's user ID

***

### senderDeviceId

> **senderDeviceId**: `number`

Sender's device ID

***

### senderUserId

> **senderUserId**: `string`

Sender's user ID

***

### sessionId

> **sessionId**: `string`

Session ID used for this message

***

### timestamp

> **timestamp**: `number`

Client timestamp for message identification.
Set by sender BEFORE encryption. Same value stored in MessageRecord.
Used for: retry request matching, delivery receipt correlation.
