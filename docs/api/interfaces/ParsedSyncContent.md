[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ParsedSyncContent

# Interface: ParsedSyncContent

The sync content that `inspectContent` reads from a plaintext.

The `type` member `'groupKeySync'` names the key of a managed group from
another own device. Code that switches on `type` must handle it.
`processIncomingEnvelope`, the Relay subscription and the receive queue
consume a group key sync and never give it to the application.
`decryptEnvelope` and the raw decrypt methods `receive`, `decryptMessage`
and `decryptMessages` return it unapplied, master key included.
An own device on an older SDK version gives the raw group key sync to
`onMessageDecrypted`, so upgrade every own device of one account in one
release.

## Properties

### attachmentId?

> `optional` **attachmentId?**: `string`

***

### conversationId?

> `optional` **conversationId?**: `string`

***

### groupKey?

> `optional` **groupKey?**: [`GroupKeySyncInput`](GroupKeySyncInput.md)

The group key of a `groupKeySync`. A custom adapter must report it for
its own group key sync encoding, with a 32-byte master key.

***

### reason?

> `optional` **reason?**: `string`

***

### recipientUserId?

> `optional` **recipientUserId?**: `string`

***

### storageId?

> `optional` **storageId?**: `string`

***

### targetUserId?

> `optional` **targetUserId?**: `string`

***

### timestamp?

> `optional` **timestamp?**: `number`

***

### type

> **type**: `"blocked"` \| `"configuration"` \| `"read"` \| `"sent"` \| `"viewOnceOpen"` \| `"mediaAttachmentDelete"` \| `"usernameState"` \| `"recipientUsername"` \| `"verificationState"` \| `"taskNotificationAck"` \| `"groupKeySync"`

***

### userId?

> `optional` **userId?**: `string`
