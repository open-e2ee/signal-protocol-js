[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / Envelope

# Interface: Envelope

Envelope for delivery (profile naming)

Server treats ciphertext as opaque bytes (zero-knowledge).

## Properties

### ciphertext

> **ciphertext**: `string` \| `Uint8Array`\<`ArrayBufferLike`\>

Encrypted payload (base64 or Uint8Array)

***

### clientMessageId?

> `optional` **clientMessageId?**: `string`

Stable client-generated send identifier for idempotent retry.

If a client retries after an unknown relay result, it should reuse the
same value so the relay can return the original accept metadata instead
of inserting a duplicate pending envelope.

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

Content hint for retry behavior per Signal Protocol.

- IMPLICIT: Ephemeral messages (typing indicators, receipts) - silently discard on failure
- RESENDABLE: Content messages - can trigger retry requests
- DEFAULT: Standard handling

Set by sender, used by recipient to decide retry behavior on decryption failure.

***

### ephemeral?

> `optional` **ephemeral?**: `boolean`

Skip persistence if recipient offline (for typing indicators, receipts).

***

### groupId?

> `optional` **groupId?**: `string`

Group ID (for group messages)

***

### id?

> `optional` **id?**: `string`

Server-assigned envelope ID (set by server)

***

### messageType

> **messageType**: `"ciphertext"` \| `"prekey_bundle"` \| `"plaintext_content"` \| `"server_delivery_receipt"` \| `"unidentified_sender"`

Relay-visible envelope type.
Client-to-client types (delivery_receipt, typing_indicator, sender_key_distribution)
are encrypted content types inside a ciphertext envelope; the relay
contract carries only the outer envelope type.

- ciphertext: Standard Double Ratchet message (contains encrypted Content)
- prekey_bundle: Session initiation (X3DH/PQXDH)
- plaintext_content: Sealed sender envelope
- server_delivery_receipt: Server-generated delivery receipts
- unidentified_sender: Sealed sender protocol messages

***

### recipientRegistrationId?

> `optional` **recipientRegistrationId?**: `number`

Recipient's registration ID from the prekey bundle.
For PreKeyMessages only. Server validates this matches recipient's current registration.
If mismatch (device reinstalled), server returns STALE_DEVICE error (equivalent to HTTP 410).

***

### senderDeviceId

> **senderDeviceId**: `number`

Sender device ID

***

### senderUserId

> **senderUserId**: `string`

Sender user ID

***

### serverTimestamp?

> `optional` **serverTimestamp?**: `number`

Server timestamp (set by server)

***

### targetDeviceId

> **targetDeviceId**: `number`

Target device ID (1-5)

***

### targetUserId

> **targetUserId**: `string`

Target user ID

***

### timestamp

> **timestamp**: `number`

Client timestamp for message identification.
Set by sender BEFORE encryption. Same value embedded in dataMessage.timestamp.
Used for: retry request matching, delivery receipt correlation, replay prevention.

***

### urgent?

> `optional` **urgent?**: `boolean`

Push notification priority (default true). Non-urgent = silent push.
