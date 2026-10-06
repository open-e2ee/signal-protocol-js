[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayProfileKeys

# Interface: HostedRelayProfileKeys

The profile keys that a hosted client carries in its 1:1 messages.

## Properties

### contacts

> `readonly` **contacts**: `MutableContactProfileStateStore`

Keeps the profile key that each contact sent. The client sends a sealed
message only to a contact whose profile key this store holds, and sends
an identified message to each other contact. The client also records
here when the Relay refuses a sealed message to a contact. It then sends
identified messages to that contact until the contact's profile key
changes.

## Methods

### getOwnProfileKey()

> **getOwnProfileKey**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Returns this account's 32-byte profile key, or null when it has none. The
SDK reads it before each 1:1 send and when the mailbox socket connects,
so a new key takes effect at the next of these. Each device of the
account must return the same key.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>
