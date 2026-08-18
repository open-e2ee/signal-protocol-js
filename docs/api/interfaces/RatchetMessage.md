[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RatchetMessage

# Interface: RatchetMessage

Complete encrypted message with Double Ratchet header

This is the wire format for messages using the full Double Ratchet.
Uses AES-256-CBC + HMAC-SHA256 per Signal Protocol specification.

Section 3 Variant (Plaintext Headers + MAC):
- The header carries the DH public key in plaintext (needed to determine key chain)
- The header carries the message counters in plaintext (PN and N)
- HMAC-SHA256 (truncated to 8 bytes) authenticates header + ciphertext
- The MAC computation includes identity keys for session binding

## See

https://signal.org/docs/specifications/doubleratchet/ (Section 3)

## Properties

### ciphertext

> **ciphertext**: [`Base64`](../type-aliases/Base64.md)

AES-CBC encrypted message body

***

### contentHint?

> `optional` **contentHint?**: [`ContentHint`](../enumerations/ContentHint.md)

Content hint for delivery and retry behavior (optional).

Helps optimize message handling without decrypting:
- DEFAULT: Normal message with standard policies
- RESENDABLE: the client can retry it if delivery fails
- IMPLICIT: Ephemeral (typing, receipts) - do not store long-term

***

### counter

> **counter**: `number`

Message counter in current sending chain (proto: counter, field 2)

***

### mac

> **mac**: [`Base64`](../type-aliases/Base64.md)

HMAC-SHA256 truncated to 8 bytes (identity-bound: includes sender/receiver identity keys)

***

### messageVersion

> **messageVersion**: `string`

Wire format version for protocol evolution.

Format 'v1' (current): JSON serialization, plaintext headers + identity-bound MAC

Allows backward/forward compatibility - recipients can gracefully handle
different versions or reject unsupported versions during decryption.

***

### previousCounter

> **previousCounter**: `number`

Number of messages in previous sending chain (proto: previous_counter, field 3)

***

### ratchetKey

> **ratchetKey**: [`PublicKey`](../type-aliases/PublicKey.md)

Sender's current ratchet public key (proto: ratchet_key, field 1)

***

### type

> **type**: [`RATCHET`](../enumerations/MessageType.md#ratchet)

Message type discriminator - enables exhaustive type checking
