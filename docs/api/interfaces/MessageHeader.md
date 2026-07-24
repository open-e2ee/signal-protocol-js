[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MessageHeader

# Interface: MessageHeader

Double Ratchet message header

Contains metadata needed for DH ratcheting and out-of-order message handling.
This header is sent with every encrypted message.

Field names reflect the SignalMessage wire fields:

## Properties

### counter

> **counter**: `number`

Message counter within the current sending chain (proto: counter, field 2).

Increments with each message sent. Used for:
- Deriving message keys from the chain key
- Detecting out-of-order and missing messages
- Indexing skipped message keys in MKSKIPPED

***

### previousCounter

> **previousCounter**: `number`

Number of messages in the previous sending chain (proto: previous_counter, field 3).

When a DH ratchet occurs, this tells the recipient how many messages
were sent in the previous chain, allowing them to store skipped keys.

***

### ratchetKey

> **ratchetKey**: [`PublicKey`](../type-aliases/PublicKey.md)

Sender's current ratchet public key (proto: ratchet_key, field 1).

This is the ephemeral DH public key used in the Double Ratchet algorithm.
When this changes, the recipient performs a DH ratchet step.
