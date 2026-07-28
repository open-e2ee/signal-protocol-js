[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / isGroupId

# Function: isGroupId()

> **isGroupId**(`id`): `id is GroupId`

Check if an ID is a group ID (has group prefix)

Type guard that narrows string to GroupId.

## Parameters

### id

`string`

Recipient ID to check

## Returns

`id is GroupId`

True if this is a group ID

## Example

```typescript
const id = 'open-e2ee:group:abc123';
if (isGroupId(id)) {
  // id is now typed as GroupId
  const raw = extractGroupId(id);
}
```
