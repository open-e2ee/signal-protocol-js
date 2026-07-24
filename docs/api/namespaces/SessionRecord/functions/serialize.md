[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / serialize

# Function: serialize()

> **serialize**(`record`): `Uint8Array`

Serialize a SessionRecord to bytes for storage.

Uses JSON serialization for simplicity and debuggability.
Future versions may use Protocol Buffers for efficiency.

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord to serialize

## Returns

`Uint8Array`

Serialized bytes
