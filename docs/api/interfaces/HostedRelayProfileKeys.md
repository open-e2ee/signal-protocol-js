[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayProfileKeys

# Interface: HostedRelayProfileKeys

The profile keys that a hosted client carries in its 1:1 messages.

## Properties

### contacts

> `readonly` **contacts**: `MutableContactProfileStateStore`

Keeps the profile key that each contact sent.

## Methods

### getOwnProfileKey()

> **getOwnProfileKey**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Returns this account's 32-byte profile key, or null when it has none. The
SDK reads it before each 1:1 send and when the mailbox socket connects,
so a new key takes effect at the next of these. Each device of the
account must return the same key.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>
