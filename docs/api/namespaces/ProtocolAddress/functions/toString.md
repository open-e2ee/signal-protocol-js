[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / toString

# Function: toString()

> **toString**(`address`): `string`

Convert a ProtocolAddress to string format.

Uses Signal Protocol standard format: "userId:deviceId"

## Parameters

### address

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

The address to serialize

## Returns

`string`

String representation "userId:deviceId"

## Example

```typescript
const address = ProtocolAddress.create('user123', 1);
ProtocolAddress.toString(address); // "user123:1"
```
