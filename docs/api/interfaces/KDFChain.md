[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KDFChain

# Interface: KDFChain

KDF Chain state for SPQR.

Each epoch maintains separate KDF chains for sending and receiving.
KDF chains derive message keys from a chain key using KDF_CK().

Signal Protocol Section 5.3:
"Each epoch e has two KDF chains: one for sending and one for receiving"

## Properties

### CK

> **CK**: [`Base64`](../type-aliases/Base64.md)

Chain key (derives message keys)

***

### N

> **N**: `number`

Message counter (number of keys derived from this chain)
