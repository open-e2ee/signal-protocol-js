[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / equals

# Function: equals()

> **equals**(`a`, `b`): `boolean`

Check if two addresses are equal.

## Parameters

### a

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

First address

### b

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Second address

## Returns

`boolean`

true if addresses are equal

## Example

```typescript
const addr1 = ProtocolAddress.create('user123', 1);
const addr2 = ProtocolAddress.create('user123', 1);
ProtocolAddress.equals(addr1, addr2); // true
```
