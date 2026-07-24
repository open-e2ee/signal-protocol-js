[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / fromStorageKey

# Function: fromStorageKey()

> **fromStorageKey**(`storageKey`): [`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Parse a storage key back into a ProtocolAddress.

## Parameters

### storageKey

`string`

Storage key in "session:userId:deviceId" format

## Returns

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Parsed ProtocolAddress

## Throws

If storage key format is invalid

## Example

```typescript
const address = ProtocolAddress.fromStorageKey('session:bob:2');
// Returns: { userId: 'bob', deviceId: 2 }
```
