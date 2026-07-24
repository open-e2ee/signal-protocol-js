[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISenderKeyStore

# Interface: ISenderKeyStore

Sender Key store interface for group messaging.

Manages sender keys for efficient group encryption using the
Sender Key Distribution Message protocol.

## Extended by

- [`ISignalLocalStore`](ISignalLocalStore.md)

## Methods

### countSkippedSenderKeys()

> **countSkippedSenderKeys**(`groupId`, `senderId`, `senderDeviceId`): `Promise`\<`number`\>

Count skipped keys for a sender (for enforcing maxSkippedKeys limit).

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

#### Returns

`Promise`\<`number`\>

Number of stored skipped keys for this sender

***

### deleteAllSenderKeysForGroup()

> **deleteAllSenderKeysForGroup**(`groupId`): `Promise`\<`number`\>

Delete all sender keys for a group (when group is deleted).

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`number`\>

***

### deleteOldestSkippedSenderKeys()

> **deleteOldestSkippedSenderKeys**(`groupId`, `senderId`, `senderDeviceId`, `count`): `Promise`\<`number`\>

Delete oldest skipped keys to make room for new ones.

Called when maxSkippedKeys limit is reached.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

##### count

`number`

Number of oldest keys to delete

#### Returns

`Promise`\<`number`\>

Number of deleted keys

***

### deleteSenderKey()

> **deleteSenderKey**(`groupId`, `userId`, `deviceId`): `Promise`\<`void`\>

Delete sender key for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

***

### deleteSkippedSenderKey()

> **deleteSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`): `Promise`\<`void`\>

Delete skipped message key after use.

Called after successfully decrypting an out-of-order message.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

##### chainIndex

`number`

The message index to delete

#### Returns

`Promise`\<`void`\>

***

### getAllSenderKeysForGroup()

> **getAllSenderKeysForGroup**(`groupId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md)[]\>

Get all sender keys for a group (for admin operations).

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md)[]\>

***

### getSenderKey()

> **getSenderKey**(`groupId`, `userId`, `deviceId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md) \| `null`\>

Retrieve sender key state for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md) \| `null`\>

***

### getSenderKeyRecord()

> **getSenderKeyRecord**(`groupId`, `userId`, `deviceId`): `Promise`\<[`SenderKeyState`](SenderKeyState.md)[] \| `null`\>

Retrieve all sender key states (current + previous) for a group member device.

First element is the current state; remaining are previous states.

#### Parameters

##### groupId

`string`

Group identifier

##### userId

`string`

User identifier

##### deviceId

`number`

Device identifier

#### Returns

`Promise`\<[`SenderKeyState`](SenderKeyState.md)[] \| `null`\>

Array of states, or null if none exist

***

### getSkippedSenderKey()

> **getSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`): `Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

Retrieve skipped message key for out-of-order decryption.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

##### chainIndex

`number`

The message index to look up

#### Returns

`Promise`\<[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md) \| `null`\>

Message key or null if not found/expired

***

### storeSenderKey()

> **storeSenderKey**(`groupId`, `userId`, `deviceId`, `state`): `Promise`\<`void`\>

Store sender key state for a group member device.

#### Parameters

##### groupId

`string`

##### userId

`string`

##### deviceId

`number`

##### state

[`SenderKeyState`](SenderKeyState.md)

#### Returns

`Promise`\<`void`\>

***

### storeSenderKeyRecord()

> **storeSenderKeyRecord**(`groupId`, `userId`, `deviceId`, `states`): `Promise`\<`void`\>

Store all sender key states (current + previous) for a group member device.

The first element is the current state; remaining are previous states
retained during the rotation window for decrypting in-flight messages.

Per Sender Keys spec Section 5.1: "Implementations MUST store sender key
state persistently." This method persists the full record atomically.

#### Parameters

##### groupId

`string`

Group identifier

##### userId

`string`

User identifier

##### deviceId

`number`

Device identifier

##### states

[`SenderKeyState`](SenderKeyState.md)[]

Array of states (current first, then previous, capped at MAX_SENDER_KEY_STATES)

#### Returns

`Promise`\<`void`\>

***

### storeSkippedSenderKey()

> **storeSkippedSenderKey**(`groupId`, `senderId`, `senderDeviceId`, `chainIndex`, `messageKey`): `Promise`\<`void`\>

Store skipped message key for out-of-order decryption.

When chain is advanced past a message (gap in chainIndex),
store the derived key so the skipped message can be decrypted later.

#### Parameters

##### groupId

`string`

Group identifier

##### senderId

`string`

Sender user identifier

##### senderDeviceId

`number`

Sender device identifier

##### chainIndex

`number`

The message index this key is for

##### messageKey

[`SkippedSenderMessageKey`](SkippedSenderMessageKey.md)

Derived IV and cipher key (base64 encoded)

#### Returns

`Promise`\<`void`\>
