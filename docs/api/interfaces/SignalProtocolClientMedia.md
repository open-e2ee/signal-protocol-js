[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientMedia

# Interface: SignalProtocolClientMedia

## Methods

### cleanup()

> **cleanup**(`input`, `options?`): `Promise`\<[`SignalProtocolClientMediaCleanupResult`](../type-aliases/SignalProtocolClientMediaCleanupResult.md)\>

#### Parameters

##### input

[`PlanMediaAttachmentCleanupJobsInput`](../namespaces/media/interfaces/PlanMediaAttachmentCleanupJobsInput.md)

##### options?

[`SignalProtocolClientMediaOperationOptions`](SignalProtocolClientMediaOperationOptions.md)

#### Returns

`Promise`\<[`SignalProtocolClientMediaCleanupResult`](../type-aliases/SignalProtocolClientMediaCleanupResult.md)\>

***

### download()

> **download**(`input`, `options?`): `Promise`\<[`SignalProtocolClientMediaDownloadResult`](../type-aliases/SignalProtocolClientMediaDownloadResult.md)\>

#### Parameters

##### input

[`PlanMediaAttachmentDownloadJobInput`](../namespaces/media/interfaces/PlanMediaAttachmentDownloadJobInput.md)

##### options?

[`SignalProtocolClientMediaOperationOptions`](SignalProtocolClientMediaOperationOptions.md)

#### Returns

`Promise`\<[`SignalProtocolClientMediaDownloadResult`](../type-aliases/SignalProtocolClientMediaDownloadResult.md)\>

***

### processPending()

> **processPending**(`options?`): `Promise`\<[`SignalProtocolClientMediaProcessResult`](SignalProtocolClientMediaProcessResult.md)\>

#### Parameters

##### options?

[`SignalProtocolClientProcessPendingMediaOptions`](SignalProtocolClientProcessPendingMediaOptions.md)

#### Returns

`Promise`\<[`SignalProtocolClientMediaProcessResult`](SignalProtocolClientMediaProcessResult.md)\>

***

### upload()

> **upload**(`input`, `options?`): `Promise`\<[`SignalProtocolClientMediaUploadResult`](../type-aliases/SignalProtocolClientMediaUploadResult.md)\>

#### Parameters

##### input

[`PlanMediaAttachmentUploadJobInput`](../namespaces/media/interfaces/PlanMediaAttachmentUploadJobInput.md)

##### options?

[`SignalProtocolClientMediaOperationOptions`](SignalProtocolClientMediaOperationOptions.md)

#### Returns

`Promise`\<[`SignalProtocolClientMediaUploadResult`](../type-aliases/SignalProtocolClientMediaUploadResult.md)\>
