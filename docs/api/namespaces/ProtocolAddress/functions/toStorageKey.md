[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [ProtocolAddress](../README.md) / toStorageKey

# Function: toStorageKey()

> **toStorageKey**(`address`): `string`

Create a storage key for looking up SessionRecords by ProtocolAddress.

Sessions are looked up by ProtocolAddress, while individual states within
a SessionRecord are identified by `baseKey`.

Format: `session:${userId}:${deviceId}`

## Parameters

### address

[`ProtocolAddress`](../../../interfaces/ProtocolAddress.md)

Remote party's protocol address

## Returns

`string`

Storage key for SessionRecord lookup

## Example

```typescript
const remoteAddr = ProtocolAddress.create('bob', 2);
const storageKey = ProtocolAddress.toStorageKey(remoteAddr);
// Returns: "session:bob:2"
```
