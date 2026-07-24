[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / createGroupId

# Function: createGroupId()

> **createGroupId**(`rawId`): [`GroupId`](../type-aliases/GroupId.md)

Create a prefixed group ID from a raw group ID

## Parameters

### rawId

`string`

Raw group ID without prefix

## Returns

[`GroupId`](../type-aliases/GroupId.md)

Prefixed group ID (branded type)

## Example

```typescript
const groupId = createGroupId('abc123');
// groupId is '__signal_group__v2__!abc123' with GroupId type
```
