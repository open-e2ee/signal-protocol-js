[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SenderKeyHandoffStore

# Interface: SenderKeyHandoffStore

The sender-key handoff ledger of the local device.

A group send gives the current own sender key to each listed device that
has no row for the current key. The store keeps the rows and deletes them.
It never decides which device needs the key. Rows have no expiry. A row
leaves the store only through an invalidation, a write that replaces or
deletes the own key, a reset of the store, or the sweep at client start.

## Extended by

- [`SignalProtocolLocalStore`](SignalProtocolLocalStore.md)

## Methods

### invalidateAccountSenderKeyHandoffs()

> **invalidateAccountSenderKeyHandoffs**(`userId`): `Promise`\<`boolean`\>

Delete the rows of every device of one account in every group, as an
identity rotation of the account does.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`boolean`\>

True when at least one row was deleted

***

### invalidateSenderKeyHandoff()

> **invalidateSenderKeyHandoff**(`groupId`, `device`): `Promise`\<`boolean`\>

Delete the rows of one device in one group.

#### Parameters

##### groupId

`string`

##### device

[`SenderKeyHandoffDevice`](SenderKeyHandoffDevice.md)

#### Returns

`Promise`\<`boolean`\>

True when at least one row was deleted

***

### listSenderKeyHandoffGroupIds()

> **listSenderKeyHandoffGroupIds**(): `Promise`\<`string`[]\>

The distinct group IDs that hold rows. For the sweep only.

#### Returns

`Promise`\<`string`[]\>

***

### listSenderKeyHandoffs()

> **listSenderKeyHandoffs**(`groupId`, `generation`): `Promise`\<[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)[]\>

The rows of one group at one generation.

#### Parameters

##### groupId

`string`

##### generation

`number`

#### Returns

`Promise`\<[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)[]\>

***

### recordSenderKeyHandoff()

> **recordSenderKeyHandoff**(`record`): `Promise`\<`void`\>

Insert or replace the row keyed by group, sender key ID, generation,
recipient user, recipient device, and recipient registration ID.

#### Parameters

##### record

[`SenderKeyHandoffRecord`](SenderKeyHandoffRecord.md)

#### Returns

`Promise`\<`void`\>

***

### retainSenderKeyHandoffs()

> **retainSenderKeyHandoffs**(`groupId`, `senderKeyId`): `Promise`\<`number`\>

Delete the rows of a group whose sender key ID differs from the given one.
Null deletes every row of the group.

#### Parameters

##### groupId

`string`

##### senderKeyId

`string` \| `null`

#### Returns

`Promise`\<`number`\>

The number of deleted rows
