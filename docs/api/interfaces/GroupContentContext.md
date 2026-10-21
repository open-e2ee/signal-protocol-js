[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupContentContext

# Interface: GroupContentContext

The context of a managed group inside the encrypted content of each
message to the group, as Signal's `GroupContextV2`. The receiver derives
the group ID from the master key and brings its group state up to the
revision before it authorizes the content.

## Properties

### groupChange?

> `optional` **groupChange?**: `Uint8Array`\<`ArrayBufferLike`\>

A signed group change to this revision, when the content carries one.

***

### masterKey

> **masterKey**: `Uint8Array`

The group master key. It is 32 bytes.

***

### revision

> **revision**: `number`

The revision of the sender's verified group state at the send.
