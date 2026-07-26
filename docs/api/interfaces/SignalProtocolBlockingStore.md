[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolBlockingStore

# Interface: SignalProtocolBlockingStore

Durable local store for blocked recipients.

## Methods

### isBlocked()

> **isBlocked**(`recipientId`): `Promise`\<`boolean`\>

#### Parameters

##### recipientId

`string`

#### Returns

`Promise`\<`boolean`\>

***

### listBlockedRecipients()

> **listBlockedRecipients**(): `Promise`\<[`BlockedRecipientEntry`](BlockedRecipientEntry.md)[]\>

#### Returns

`Promise`\<[`BlockedRecipientEntry`](BlockedRecipientEntry.md)[]\>

***

### removeBlockedRecipient()

> **removeBlockedRecipient**(`recipientId`): `Promise`\<`void`\>

#### Parameters

##### recipientId

`string`

#### Returns

`Promise`\<`void`\>

***

### replaceBlockedRecipients()

> **replaceBlockedRecipients**(`entries`): `Promise`\<`void`\>

#### Parameters

##### entries

readonly [`BlockedRecipientEntry`](BlockedRecipientEntry.md)[]

#### Returns

`Promise`\<`void`\>

***

### upsertBlockedRecipient()

> **upsertBlockedRecipient**(`entry`): `Promise`\<`void`\>

#### Parameters

##### entry

[`BlockedRecipientEntry`](BlockedRecipientEntry.md)

#### Returns

`Promise`\<`void`\>
