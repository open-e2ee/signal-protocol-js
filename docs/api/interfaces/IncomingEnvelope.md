[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IncomingEnvelope

# Interface: IncomingEnvelope

Incoming message envelope structure.

Matches both relay subscription envelopes and background pending messages.
Used by processIncomingEnvelope() for unified message handling.

## Properties

### ciphertext

> **ciphertext**: `string`

Base64-encoded ciphertext

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

Content hint for retry behavior per Signal Protocol.

- IMPLICIT: Ephemeral messages (typing indicators, receipts) - silently discard on failure
- RESENDABLE: Content messages - can trigger retry requests
- DEFAULT: Standard handling

If not set, behavior is inferred from messageType via IMPLICIT_ENVELOPE_TYPES.

***

### groupId?

> `optional` **groupId?**: `string`

Group ID for group messages

***

### id

> **id**: `string`

Server-assigned message ID

***

### messageType?

> `optional` **messageType?**: `string`

Message type for filtering (ciphertext, prekey_bundle, etc.)

***

### senderDeviceId

> **senderDeviceId**: `number`

Sender's device ID

***

### senderUserId

> **senderUserId**: `string`

Sender's user ID (Convex _id)

***

### serverTimestamp?

> `optional` **serverTimestamp?**: `number`

Server timestamp when message was received

***

### timestamp

> **timestamp**: `number`

Client timestamp for message identification.
Set by sender BEFORE encryption. Used for retry requests and replay prevention.
