[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PendingReceive

# Interface: PendingReceive

One receive that `processIncomingEnvelope` stored and did not complete.

## Properties

### groupId?

> `optional` **groupId?**: `string`

***

### hookAttempts

> **hookAttempts**: `number`

The calls of `onMessageDecrypted` that started for this receive and
did not complete it. At the cap of 10 attempts, the receive holds back
no later receive, and each start offers it to the hook once.

***

### messageId

> **messageId**: `string`

The ID that `completeReceive` and `discardPendingReceive` take. A
receive stored before the client kept message IDs gives its record ID.

***

### origin

> **origin**: `"caller"` \| `"relay"`

`caller` for an envelope that the application gave.

***

### plaintext?

> `optional` **plaintext?**: `string`

The content of a ready receive, as its sender gave it.

***

### receivedAt

> **receivedAt**: `number`

The time of the first decrypt.

***

### senderDeviceId?

> `optional` **senderDeviceId?**: `number`

***

### senderId?

> `optional` **senderId?**: `string`

***

### stage

> **stage**: `"decrypted"` \| `"awaiting-completion"`

`awaiting-completion` when the content is ready and waits for
`completeReceive`. `decrypted` when it waits for its group state.
