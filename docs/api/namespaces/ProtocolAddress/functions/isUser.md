[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / isUser

# Function: isUser()

> **isUser**(`address`, `userId`): `boolean`

Check if address belongs to a specific user (ignoring device).

## Parameters

### address

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Address to check

### userId

`string`

User ID to match

## Returns

`boolean`

true if address belongs to userId

## Example

```typescript
const address = ProtocolAddress.create('user123', 1);
ProtocolAddress.isUser(address, 'user123'); // true
ProtocolAddress.isUser(address, 'user456'); // false
```
