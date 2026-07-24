[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / parse

# Function: parse()

> **parse**(`address`): [`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Parse a string address into a ProtocolAddress.

Expected format: "userId:deviceId" (Signal Protocol standard)

## Parameters

### address

`string`

String address in "userId:deviceId" format

## Returns

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Parsed ProtocolAddress

## Throws

If address format is invalid

## Example

```typescript
const address = ProtocolAddress.parse('user123:1');
// { userId: 'user123', deviceId: 1 }

ProtocolAddress.parse('invalid');
// Error: Invalid address format
```
