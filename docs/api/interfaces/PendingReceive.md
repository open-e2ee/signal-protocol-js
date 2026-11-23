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

The ID that `completeReceive` and `discardPendingReceive` take.

***

### origin

> **origin**: `"caller"` \| `"relay"` \| `"signal-relay"`

`signal-relay` for a Relay message, `caller` for an envelope that the
application gave. `relay` is the same origin as `signal-relay`. SDK 14
reported a Relay message with `relay`. This release does not report it.
The type keeps it, so code that compares the origin with both values
compiles.

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
