[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MessageRecord

# Interface: MessageRecord

MessageRecord for SESAME retry request resending

Per SESAME Specification Section 4.1:

> "Each MessageRecord stores the following values:
>  - The plaintext of the encrypted message
>  - The UserID for the recipient device
>  - The SessionID for the session the message was encrypted with"

The SessionID detects orphaned sessions during resending:

> "If the DeviceRecord's active session matches the SessionID from the
> relevant MessageRecord, then the sending device creates a new initiating
> session... This prevents the sending device from repeatedly sending a
> message using an orphaned session which does not match any recipient
> session."

The client timestamp assigned before encryption indexes a message.
Retry count enforces SESAME's bounded-resend requirement.

## Properties

### createdAt

> **createdAt**: `number`

Timestamp when the store created the record

***

### plaintext

> **plaintext**: `string`

Original plaintext message (stored for resending)

***

### recipientDeviceId

> **recipientDeviceId**: `number`

Recipient's device ID

***

### recipientUserId

> **recipientUserId**: `string`

Recipient's user ID

***

### sessionId

> **sessionId**: `string`

Device address (userId:deviceId format) for the recipient device

***

### sessionStateId

> **sessionStateId**: `string`

Sender's ratchet key (DHs.publicKey) at send time, for retry session matching.

If the sender's current DHs differs from this stored value, the DH ratchet
advanced and the session is healthy. Reuse it. If it matches, the session has not
advanced and may need a fresh bundle.

***

### timestamp

> **timestamp**: `number`

Client timestamp for message identification.
Set by sender BEFORE encryption. Used for retry request matching.
This is the PRIMARY key for message lookup.
