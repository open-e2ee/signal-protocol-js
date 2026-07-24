[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MLKEMBraidMessage

# Interface: MLKEMBraidMessage

ML-KEM Braid protocol message

## Properties

### chunkIndex?

> `optional` **chunkIndex?**: `number`

Chunk index for out-of-order delivery support (0-based)

***

### data?

> `optional` **data?**: `Uint8Array`\<`ArrayBufferLike`\>

Erasure code chunk (when applicable)

***

### epoch

> **epoch**: `bigint`

Current negotiation epoch (uint64)

***

### type

> **type**: `MessageType`

Message type

***

### versionCapability?

> `optional` **versionCapability?**: `VersionCapability`

Version capability (only during negotiation)
