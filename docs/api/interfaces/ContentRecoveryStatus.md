[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ContentRecoveryStatus

# Interface: ContentRecoveryStatus

The content recovery decision of a client. The client makes it at
creation from the protection that the local store declares and from
`protocol.contentRecovery`. It does not change while the client runs.

When `enabled` is false, the client keeps no resendable content. A retry
request for a direct message then resets the session with no content, and
a group message is sent with the `Default` content hint instead of
`Resendable`.

## Properties

### atRest

> `readonly` **atRest**: `LocalStoreAtRest`

***

### enabled

> `readonly` **enabled**: `boolean`

***

### groupMembershipSource

> `readonly` **groupMembershipSource**: [`GroupMembershipSource`](../type-aliases/GroupMembershipSource.md)

The group membership source that a group resend uses.

***

### keyCustody

> `readonly` **keyCustody**: `LocalStoreKeyCustody`

***

### level

> `readonly` **level**: [`StorageProtectionLevel`](../type-aliases/StorageProtectionLevel.md)

***

### mode

> `readonly` **mode**: [`ContentRecoveryMode`](../type-aliases/ContentRecoveryMode.md)

***

### reason?

> `readonly` `optional` **reason?**: [`ContentRecoveryDisabledReason`](../type-aliases/ContentRecoveryDisabledReason.md)

Set only when `enabled` is false.
