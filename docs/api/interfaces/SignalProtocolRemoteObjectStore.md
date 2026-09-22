[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolRemoteObjectStore

# Interface: SignalProtocolRemoteObjectStore

Brokered remote storage for encrypted byte objects.

Implementations request narrowly scoped, short-lived operations from an
authenticated application backend. Cloud credentials and unrestricted
storage clients must never reach an app runtime.

## Methods

### abandonUpload()?

> `optional` **abandonUpload**(`input`): `Promise`\<`void`\>

Refuse the original upload identity and delete its accepted object, if present.
Never create an upload to find it. Preserve accepted accounting. Resolve only
after durable refusal owns cleanup. A repeated request must be safe.

#### Parameters

##### input

`Pick`\<[`RemoteObjectUploadRequest`](../type-aliases/RemoteObjectUploadRequest.md), `"requestId"` \| `"preparedAt"`\>

#### Returns

`Promise`\<`void`\>

***

### completeUpload()?

> `optional` **completeUpload**(`input`): `Promise`\<`void`\>

Finalize provider metadata after a successful upload, when required.

Implementations must make this operation idempotent because a client may
retry it after an interrupted upload workflow.

#### Parameters

##### input

[`RemoteObjectCompleteUploadRequest`](../type-aliases/RemoteObjectCompleteUploadRequest.md)

#### Returns

`Promise`\<`void`\>

***

### createDownload()

> **createDownload**(`input`): `Promise`\<[`RemoteObjectDownload`](RemoteObjectDownload.md)\>

Create a short-lived direct download operation.

#### Parameters

##### input

[`RemoteObjectDownloadRequest`](../type-aliases/RemoteObjectDownloadRequest.md)

#### Returns

`Promise`\<[`RemoteObjectDownload`](RemoteObjectDownload.md)\>

***

### createUpload()

> **createUpload**(`input`): `Promise`\<[`RemoteObjectUpload`](RemoteObjectUpload.md)\>

Create a short-lived direct upload operation.

#### Parameters

##### input

[`RemoteObjectUploadRequest`](../type-aliases/RemoteObjectUploadRequest.md)

#### Returns

`Promise`\<[`RemoteObjectUpload`](RemoteObjectUpload.md)\>

***

### deleteObject()?

> `optional` **deleteObject**(`input`): `Promise`\<`void`\>

Delete an encrypted object, when supported by the backend.

#### Parameters

##### input

[`RemoteObjectDeleteRequest`](../type-aliases/RemoteObjectDeleteRequest.md)

#### Returns

`Promise`\<`void`\>

***

### reconcileUpload()?

> `optional` **reconcileUpload**(`input`): `Promise`\<[`RemoteObjectUploadReceipt`](RemoteObjectUploadReceipt.md) \| `null`\>

Recover an uncertain transfer using the original authorized object.

Return a receipt only after verifying stored bytes and completing the
backend's acceptance transition. Return null only when bytes are absent
and the original authorization remains valid. Throw on unknown outcomes,
mismatch, deletion, or expiry. Never reserve another object here.
Omit this capability when the backend cannot provide that proof.

#### Parameters

##### input

[`RemoteObjectCompleteUploadRequest`](../type-aliases/RemoteObjectCompleteUploadRequest.md)

#### Returns

`Promise`\<[`RemoteObjectUploadReceipt`](RemoteObjectUploadReceipt.md) \| `null`\>
