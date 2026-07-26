[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolContentAdapter

# Interface: SignalProtocolContentAdapter

## Methods

### areReadReceiptsEnabled()

> **areReadReceiptsEnabled**(): `Promise`\<`boolean`\>

#### Returns

`Promise`\<`boolean`\>

***

### areTypingIndicatorsEnabled()

> **areTypingIndicatorsEnabled**(): `Promise`\<`boolean`\>

#### Returns

`Promise`\<`boolean`\>

***

### inspectContent()

> **inspectContent**(`plaintext`): [`InspectedSignalProtocolContent`](InspectedSignalProtocolContent.md)

#### Parameters

##### plaintext

`string`

#### Returns

[`InspectedSignalProtocolContent`](InspectedSignalProtocolContent.md)

***

### serializeBlockedRecipientsSync()

> **serializeBlockedRecipientsSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`BlockedRecipientsSyncInput`](BlockedRecipientsSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeConfigurationSync()

> **serializeConfigurationSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`ConfigurationSyncInput`](ConfigurationSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeDataMessage()

> **serializeDataMessage**(`content`): `Uint8Array`

#### Parameters

##### content

[`DataMessageInput`](DataMessageInput.md)

#### Returns

`Uint8Array`

***

### serializeMediaAttachmentDeleteSync()

> **serializeMediaAttachmentDeleteSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`MediaAttachmentDeleteSyncInput`](MediaAttachmentDeleteSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeNullMessage()

> **serializeNullMessage**(): `string`

#### Returns

`string`

***

### serializeReadSync()

> **serializeReadSync**(`entries`): `Uint8Array`

#### Parameters

##### entries

[`ReadSyncEntryInput`](ReadSyncEntryInput.md)[]

#### Returns

`Uint8Array`

***

### serializeReceipt()

> **serializeReceipt**(`type`, `timestamps`): `string`

#### Parameters

##### type

`"DELIVERY"` \| `"READ"` \| `"VIEWED"`

##### timestamps

`number`[]

#### Returns

`string`

***

### serializeRecipientUsernameSync()

> **serializeRecipientUsernameSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`RecipientUsernameSyncInput`](RecipientUsernameSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeSenderKeyDistributionBytes()

> **serializeSenderKeyDistributionBytes**(`groupId`, `distribution`): `Uint8Array`

#### Parameters

##### groupId

`string`

##### distribution

[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md)

#### Returns

`Uint8Array`

***

### serializeSenderKeyDistributionText()

> **serializeSenderKeyDistributionText**(`groupId`, `distribution`): `string`

#### Parameters

##### groupId

`string`

##### distribution

[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md)

#### Returns

`string`

***

### serializeSentTranscript()

> **serializeSentTranscript**(`input`): `Uint8Array`

#### Parameters

##### input

[`SentSyncTranscriptInput`](SentSyncTranscriptInput.md)

#### Returns

`Uint8Array`

***

### serializeTaskNotificationAckSync()

> **serializeTaskNotificationAckSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`TaskNotificationAckSyncInput`](TaskNotificationAckSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeTyping()

> **serializeTyping**(`action`, `groupId?`): `string`

#### Parameters

##### action

`"STARTED"` \| `"STOPPED"`

##### groupId?

`string`

#### Returns

`string`

***

### serializeUsernameStateSync()

> **serializeUsernameStateSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`UsernameStateSyncInput`](UsernameStateSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeVerificationStateSync()

> **serializeVerificationStateSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`VerificationStateSyncInput`](VerificationStateSyncInput.md)

#### Returns

`Uint8Array`

***

### serializeViewOnceOpenSync()

> **serializeViewOnceOpenSync**(`input`): `Uint8Array`

#### Parameters

##### input

[`ViewOnceOpenSyncInput`](ViewOnceOpenSyncInput.md)

#### Returns

`Uint8Array`

***

### setRelayBatching()

> **setRelayBatching**(`active`): `void`

#### Parameters

##### active

`boolean`

#### Returns

`void`
