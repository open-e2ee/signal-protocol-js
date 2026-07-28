[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DecryptedGroup

# Interface: DecryptedGroup

Decrypted group state. Matches DecryptedGroup in DecryptedGroups.proto.

This is the canonical local representation of group state. It is derived
from EncryptedGroup by decrypting with GroupSecretParams.

## Properties

### accessControl

> **accessControl**: `AccessControl`

***

### avatar

> **avatar**: `string`

***

### bannedMembers

> **bannedMembers**: `DecryptedBannedMember`[]

***

### description

> **description**: `string`

***

### disappearingMessagesTimer

> **disappearingMessagesTimer**: `DecryptedTimer`

***

### inviteLinkPassword

> **inviteLinkPassword**: `Uint8Array`

***

### isAnnouncementGroup

> **isAnnouncementGroup**: `EnabledState`

***

### members

> **members**: `DecryptedMember`[]

***

### pendingMembers

> **pendingMembers**: `DecryptedPendingMember`[]

***

### requestingMembers

> **requestingMembers**: `DecryptedRequestingMember`[]

***

### revision

> **revision**: `number`

Sequential revision counter (0-based, increments with each change).

***

### terminated

> **terminated**: `boolean`

***

### title

> **title**: `string`
