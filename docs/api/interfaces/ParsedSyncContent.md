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

The `type` member `'firstSync'` names the first-sync bundle that device 1
gives a newly linked own device. The same three receive paths consume it
and give it to `hosted.onFirstSync`, never to `onMessageDecrypted`. The
raw decrypt methods return it unapplied. An own device on an older SDK
version gives it to `onMessageDecrypted`.

## Properties

### attachmentId?

> `optional` **attachmentId?**: `string`

***

### conversationId?

> `optional` **conversationId?**: `string`

***

### firstSync?

> `optional` **firstSync?**: [`FirstSyncInput`](FirstSyncInput.md)

The bundle of a `firstSync`, with its byte fields decoded. A custom
adapter must report it for its own first-sync encoding. Without it, the
client consumes the sync as malformed.

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

> **type**: `"blocked"` \| `"configuration"` \| `"read"` \| `"sent"` \| `"viewOnceOpen"` \| `"mediaAttachmentDelete"` \| `"usernameState"` \| `"recipientUsername"` \| `"verificationState"` \| `"taskNotificationAck"` \| `"groupKeySync"` \| `"firstSync"`

***

### userId?

> `optional` **userId?**: `string`

***

### verificationState?

> `optional` **verificationState?**: [`VerificationStateSyncInput`](VerificationStateSyncInput.md)

The state of a `verificationState`. A custom adapter must report it for
its own verification state encoding. Without it, the client does not
apply the sync.
