[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupId

# Type Alias: GroupId

> **GroupId** = `string` & `object`

Branded type for prefixed group IDs

Ensures compile-time safety for group ID handling.
A GroupId is always a string with the Signal Protocol V2 prefix.

## Type Declaration

### \[\_\_\_brand\_groupId\]

> `readonly` **\[\_\_\_brand\_groupId\]**: `true`

## Example

```typescript
const groupId: GroupId = createGroupId('abc123');
// groupId is '__signal_group__v2__!abc123' with GroupId type
```
