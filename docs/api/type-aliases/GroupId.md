[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupId

# Type Alias: GroupId

> **GroupId** = `string` & `object`

Branded type for prefixed group IDs

Ensures compile-time safety for group ID handling.
A GroupId is always a string with the OpenE2EE group prefix.

## Type Declaration

### \[\_\_\_brand\_groupId\]

> `readonly` **\[\_\_\_brand\_groupId\]**: `true`

## Example

```typescript
const groupId: GroupId = createGroupId('abc123');
// groupId is 'open-e2ee:group:abc123' with GroupId type
```
