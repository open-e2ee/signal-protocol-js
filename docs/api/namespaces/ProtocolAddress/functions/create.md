[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / create

# Function: create()

> **create**(`userId`, `deviceId`): [`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Create a new ProtocolAddress.

## Parameters

### userId

`string`

User identifier

### deviceId

`number`

Device identifier (must be non-negative)

## Returns

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

A new ProtocolAddress

## Throws

If userId is empty or deviceId is negative

## Example

```typescript
const address = ProtocolAddress.create('user123', 1);
```
