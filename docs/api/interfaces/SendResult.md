[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SendResult

# Interface: SendResult

Result from SignalProtocolClient.send()

Provides uniform response regardless of content type (string/Blob) or
recipient type (user/group).

## Properties

### aesKey?

> `optional` **aesKey?**: `string`

Base64-encoded AES-256 master key

***

### clientMessageId

> **clientMessageId**: `string`

Stable logical-send identifier used by the exact-ciphertext outbox.

***

### clientTimestamp?

> `optional` **clientTimestamp?**: `number`

Client timestamp from the proto.
Use this for storing outgoing messages to enable receipt matching.

***

### contentType?

> `optional` **contentType?**: `string`

MIME content type for the encrypted media

***

### digest?

> `optional` **digest?**: `string`

Base64-encoded SHA-256 digest for the encrypted blob

***

### duplicate?

> `optional` **duplicate?**: `boolean`

True when the relay had already accepted every device post of this send,
so the send stored no new copy. This is the case when the application
calls `send()` again with the `clientMessageId` of a send whose posts the
relay accepted but whose result did not arrive. For a group send over a
group token, the shared post reports that the relay had already accepted
its fan-out, not that each destination stored a copy. The sender key
pre-messages of a group send do not count. Absent when a post did not
report it, as on a relay that does not report it.

***

### expiresAt?

> `optional` **expiresAt?**: `number`

The earliest time, in milliseconds since the epoch, at which the relay
drops the copy of a device post that the device has not acknowledged.
The sender key pre-messages of a group send do not count. Absent when a
post did not report it.

***

### groupId?

> `optional` **groupId?**: `string`

Group ID if sent to a group

***

### messageId

> **messageId**: `string`

Server-assigned message ID for tracking and markAsRead()

***

### recipientDeviceCount

> **recipientDeviceCount**: `number`

Number of recipient devices that the relay accepted a copy of the message
for. Acceptance is not delivery: a device receives its copy when it next
reads its mailbox.

***

### segmentSize?

> `optional` **segmentSize?**: `number`

Segment size for streaming AEAD format

***

### storageId?

> `optional` **storageId?**: `string`

Opaque remote object identifier for the encrypted attachment

***

### timestamp

> **timestamp**: `number`

Server timestamp when the relay accepted the message
