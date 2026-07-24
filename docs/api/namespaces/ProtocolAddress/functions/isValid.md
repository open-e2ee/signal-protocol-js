[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / isValid

# Function: isValid()

> **isValid**(`address`): `boolean`

Validate that a string is a valid address format.

Optimized to avoid exception overhead by using internal tryParse().

## Parameters

### address

`string`

String to validate

## Returns

`boolean`

true if valid address format

## Example

```typescript
ProtocolAddress.isValid('user123:1'); // true
ProtocolAddress.isValid('invalid');   // false
```
