[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ReceiverChain

# Interface: ReceiverChain

Receiver chain with skipped message keys.

The SDK maintains up to MAX_RECEIVER_CHAINS (5) receiver chains
to handle out-of-order DH ratchets.

## Properties

### chainKey

> **chainKey**: [`Base64`](../type-aliases/Base64.md) \| `null`

Chain key for deriving more message keys (proto: chain_key, field 2).

May be null if chain key is no longer needed (all expected messages received).

***

### messageKeys

> **messageKeys**: `StoredMessageKey`[]

Skipped message keys (proto: message_keys, field 3).

Keys are stored when messages arrive out of order. When the skipped
message arrives, its key is consumed (removed) from this array.

***

### senderRatchetKey

> **senderRatchetKey**: [`Base64`](../type-aliases/Base64.md)

Sender's ratchet public key (proto: sender_ratchet_key, field 1).

Identifies which DH ratchet epoch this chain belongs to.
