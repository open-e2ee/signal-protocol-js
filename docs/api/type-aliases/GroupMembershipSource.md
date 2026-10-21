[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupMembershipSource

# Type Alias: GroupMembershipSource

> **GroupMembershipSource** = `"managed"` \| `"hook"` \| `"none"`

Where the client finds whether a user is a current member of a group,
before it gives group content to a device again.

- `managed`: `groups` with `resolveAciBytesByUserIds`. The client checks
  a managed group against its verified group state. When
  `isCurrentMember` is also set, it answers for an ad hoc group.
- `hook`: only `protocol.contentRecovery.isCurrentMember`. It answers for
  an ad hoc group. A resend for a managed group is refused.
- `none`: no source. Each group resend is refused. A direct message
  resend needs no source.
