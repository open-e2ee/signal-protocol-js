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

Number of recipient devices that received the message

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
