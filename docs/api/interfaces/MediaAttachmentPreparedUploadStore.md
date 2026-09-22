[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MediaAttachmentPreparedUploadStore

# Interface: MediaAttachmentPreparedUploadStore

Application-owned storage for encrypted files and their private pointer material.
Store records outside queue metadata. Protect them like the device-local store.

## Methods

### createIfAbsent()

> **createIfAbsent**(`upload`): `Promise`\<[`PreparedMediaAttachmentUpload`](PreparedMediaAttachmentUpload.md)\>

Atomically persist the complete record only if its request ID is absent.
Return an independent copy of the durable winner, including after concurrent calls.
Resolve only after ciphertext and private pointer material are durable together.
Never replace a record or expire it without the owning queue's delete call.

#### Parameters

##### upload

[`PreparedMediaAttachmentUpload`](PreparedMediaAttachmentUpload.md)

#### Returns

`Promise`\<[`PreparedMediaAttachmentUpload`](PreparedMediaAttachmentUpload.md)\>

***

### delete()

> **delete**(`requestId`): `Promise`\<`void`\>

Delete the exact record. Repeated deletion must succeed.

#### Parameters

##### requestId

`string`

#### Returns

`Promise`\<`void`\>

***

### load()

> **load**(`requestId`): `Promise`\<[`PreparedMediaAttachmentUpload`](PreparedMediaAttachmentUpload.md) \| `null`\>

Return an independent copy, or null when no preparation exists.

#### Parameters

##### requestId

`string`

#### Returns

`Promise`\<[`PreparedMediaAttachmentUpload`](PreparedMediaAttachmentUpload.md) \| `null`\>

***

### withExclusiveAccess()

> **withExclusiveAccess**\<`T`\>(`operation`): `Promise`\<`T`\>

Exclude other queue mutations against this store until the callback settles.
Coordinate every client, tab, and process that shares the files. Process exit
must release ownership. A timestamp must never authorize lock takeover.

The callback uses this store's methods. Do not take the same lock again.
The SDK uses this boundary for local queue checks and artifact mutations only.

#### Type Parameters

##### T

`T`

#### Parameters

##### operation

() => `Promise`\<`T`\>

#### Returns

`Promise`\<`T`\>
