[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolBlockingManager

# Class: SignalProtocolBlockingManager

SDK blocking orchestration.

The local store is authoritative for the current device. Optional mirrors can
project that state elsewhere without becoming a second mutation path.

## Constructors

### Constructor

> **new SignalProtocolBlockingManager**(`options`): `SignalProtocolBlockingManager`

#### Parameters

##### options

[`SignalProtocolBlockingManagerOptions`](../interfaces/SignalProtocolBlockingManagerOptions.md)

#### Returns

`SignalProtocolBlockingManager`

## Methods

### applySyncSnapshot()

> **applySyncSnapshot**(`entries`): `Promise`\<`void`\>

#### Parameters

##### entries

readonly [`BlockedRecipientEntry`](../interfaces/BlockedRecipientEntry.md)[]

#### Returns

`Promise`\<`void`\>

***

### blockRecipient()

> **blockRecipient**(`recipientId`, `blockedAt?`): `Promise`\<[`BlockedRecipientEntry`](../interfaces/BlockedRecipientEntry.md)\>

#### Parameters

##### recipientId

`string`

##### blockedAt?

`number` = `...`

#### Returns

`Promise`\<[`BlockedRecipientEntry`](../interfaces/BlockedRecipientEntry.md)\>

***

### isBlocked()

> **isBlocked**(`recipientId`): `Promise`\<`boolean`\>

#### Parameters

##### recipientId

`string`

#### Returns

`Promise`\<`boolean`\>

***

### listBlockedRecipients()

> **listBlockedRecipients**(): `Promise`\<[`BlockedRecipientEntry`](../interfaces/BlockedRecipientEntry.md)[]\>

#### Returns

`Promise`\<[`BlockedRecipientEntry`](../interfaces/BlockedRecipientEntry.md)[]\>

***

### unblockRecipient()

> **unblockRecipient**(`recipientId`): `Promise`\<`void`\>

#### Parameters

##### recipientId

`string`

#### Returns

`Promise`\<`void`\>
