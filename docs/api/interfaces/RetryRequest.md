[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryRequest

# Interface: RetryRequest

Retry request message sent when decryption fails
Unencrypted message requesting sender to resend with updated session state

## Properties

### failedTimestamp

> **failedTimestamp**: `number`

Timestamp of the message that failed to decrypt.
Used to look up original message in MessageSendLog for resend.

***

### originalSenderDeviceId

> **originalSenderDeviceId**: `number`

Original sender's device ID

***

### originalSenderUserId

> **originalSenderUserId**: `string`

Original sender's user ID

***

### ratchetKey?

> `optional` **ratchetKey?**: `string`

Sender ratchet key from the failed message (1:1 messages only).

Allows the sender to verify that a session-reset request targets the active
ratchet.

Undefined for sender-key/group failures.

***

### reason

> **reason**: `RetryReason`

Reason for retry (for debugging/logging)

***

### requesterDeviceId

> **requesterDeviceId**: `number`

Requester's device ID

***

### requesterUserId

> **requesterUserId**: `string`

Requester's user ID

***

### timestamp

> **timestamp**: `number`

Timestamp of this retry request
