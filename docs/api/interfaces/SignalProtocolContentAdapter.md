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

### serializeContentBesideSenderKeyDistribution()

> **serializeContentBesideSenderKeyDistribution**(`content`, `groupId`, `distribution`): `string`

The logged content of a group message with a sender-key distribution
beside it, in one payload. A sender answers a retry request for a group
message with it, so the requesting device gets the content and the
current sender key of the group in one resend. `inspectContent` must
report the distribution of the result, and the result must give the
content to the application as the original message.

#### Parameters

##### content

`string`

The plaintext of the group message, as the send logged it

##### groupId

`string`

The raw group ID

##### distribution

[`SenderKeyDistributionMessage`](SenderKeyDistributionMessage.md)

The current sender-key distribution of the sender

#### Returns

`string`

#### Throws

Error when the content cannot carry a distribution

***

### serializeContentWithGroupContext()

> **serializeContentWithGroupContext**(`content`, `context`): `Uint8Array`

The content of a managed group message with the group context in it.
The client calls it once for each new send to a managed group, and the
sent-sync transcript and each resend carry the result. Every content
must be able to carry a context. `inspectContent` must report the
context of the result, and `withoutGroupContext` must give the content
back.

#### Parameters

##### content

`Uint8Array`

The content that the application sends

##### context

[`GroupContentContext`](GroupContentContext.md)

The context of the group at the send

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

***

### withoutGroupContext()

> **withoutGroupContext**(`plaintext`): `string`

The content that the application gets, with no group context in it.
Return the plaintext unchanged when it carries no context. Apply the
same rule to the content inside a sent-sync transcript in this
adapter's format.

#### Parameters

##### plaintext

`string`

The decrypted plaintext

#### Returns

`string`

***

### withoutSenderKeyDistribution()

> **withoutSenderKeyDistribution**(`plaintext`): `string` \| `null`

The plaintext that a pairwise message record keeps, with no sender-key
distribution in it. A distribution holds the chain key of a group
sender key, and that key rests only in the sender key store.

Return the plaintext unchanged when it carries no distribution. Return
the other content when a distribution travels beside it, so the record
stays resendable. Return null when the distribution is all it carries.
Apply the same rule to the content inside a sent-sync transcript in
this adapter's format, because the client syncs a sent distribution to
its other devices.

#### Parameters

##### plaintext

`string`

The plaintext of a pairwise send

#### Returns

`string` \| `null`

The plaintext to keep, or null to keep no record
