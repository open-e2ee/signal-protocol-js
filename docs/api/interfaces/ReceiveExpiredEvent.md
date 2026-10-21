[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ReceiveExpiredEvent

# Interface: ReceiveExpiredEvent

Received content that waited on this device for 30 days. The client
drops it after the hook.

## Properties

### failedEnvelopeId?

> `optional` **failedEnvelopeId?**: `string`

The failed envelope that the content resends, for a resend.

***

### groupId?

> `optional` **groupId?**: `string`

The raw group of the content, when known.

***

### messageId?

> `optional` **messageId?**: `string`

The message ID. Absent for content stored before the receive queue.

***

### origin

> **origin**: `"caller"` \| `"relay"`

`relay` for a Relay message, `caller` for a helper receive.

***

### reason

> **reason**: `"max-age"`

Why the content expired.

***

### receivedAt

> **receivedAt**: `number`

When the device first admitted the content, in epoch milliseconds.

***

### senderDeviceId?

> `optional` **senderDeviceId?**: `number`

The sender device. Absent for content stored before the receive queue.

***

### senderId?

> `optional` **senderId?**: `string`

The sender. Absent for content stored before the receive queue.

***

### stage

> **stage**: `"decrypted"` \| `"awaiting-completion"`

Where the content waited: `decrypted` for content that the client did
not deliver yet, `awaiting-completion` for a helper receive that the
application did not complete.

***

### workId

> **workId**: `string`

The receive record ID: the delivered fingerprint of the envelope.
