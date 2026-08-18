[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ContentHint

# Enumeration: ContentHint

Content hint for message delivery and retry behavior.

Numeric values are part of the sealed-sender wire format and must remain
synchronized with its protobuf schema.

From Signal Protocol:
"Content hints allow the client to make informed decisions about
message resendability and storage without decrypting the message."

## Enumeration Members

### Default

> **Default**: `0`

Default behavior - no special handling.

The client treats the message as a normal user message, with standard
retry and storage policies.

***

### Implicit

> **Implicit**: `2`

Implicit/ephemeral message - do not store long-term.

Examples:
- Typing indicators
- Read receipts
- Delivery receipts
- Presence updates

Implicit messages:
- Should not be resent if delivery fails
- The store may discard them to save storage space
- Have lower priority in delivery queue
- Do not contribute to unread counts

***

### Resendable

> **Resendable**: `1`

Message can be safely resent if delivery fails.

Examples:
- Text messages
- Media with permanent URLs
- Messages that are not time-sensitive

The client can retry a resendable message multiple times with exponential
backoff if delivery fails.
