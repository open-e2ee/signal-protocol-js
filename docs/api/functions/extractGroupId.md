[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / extractGroupId

# Function: extractGroupId()

> **extractGroupId**(`groupId`): `string`

Extract raw group ID from prefixed group ID

## Parameters

### groupId

`string` \| [`GroupId`](../type-aliases/GroupId.md)

Group ID with prefix (or plain string)

## Returns

`string`

Raw group ID without prefix

## Example

```typescript
extractGroupId('open-e2ee:group:abc123'); // 'abc123'
extractGroupId('abc123');                 // 'abc123' (no prefix)
```
