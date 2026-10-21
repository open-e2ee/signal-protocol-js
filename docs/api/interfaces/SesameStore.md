[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SesameStore

# Interface: SesameStore

SESAME store interface for multi-device session management.

Implements the SESAME algorithm for automatic session convergence
across multiple devices.

Each `DeviceRecord` holds its session state directly.

## See

https://signal.org/docs/specifications/sesame/

## Extended by

- [`SignalProtocolLocalStore`](SignalProtocolLocalStore.md)

## Methods

### cleanupExpiredSessions()

> **cleanupExpiredSessions**(`maxRecv`): `Promise`\<`number`\>

Delete expired sessions (sessions older than MAXRECV threshold).

#### Parameters

##### maxRecv

`number`

#### Returns

`Promise`\<`number`\>

***

### deleteDeviceRecord()

> **deleteDeviceRecord**(`userId`, `deviceId`): `Promise`\<`void`\>

Delete device record. The same write deletes the sender-key handoff rows
of the device in every group.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<`void`\>

***

### deleteStaleRecords()

> **deleteStaleRecords**(`maxLatency`): `Promise`\<`number`\>

Delete the stale device records with their sessions. A record is stale
when it has no session and is older than `maxLatency`, or when it is
marked removed and its removal is older than `maxLatency`
(`isExpiredRemovedDevice`). A user record with no device left goes too.

#### Parameters

##### maxLatency

`number`

#### Returns

`Promise`\<`number`\>

***

### getAllUserIds()

> **getAllUserIds**(): `Promise`\<`string`[]\>

Get all user IDs with SESAME records.

#### Returns

`Promise`\<`string`[]\>

***

### getDeviceRecord()

> **getDeviceRecord**(`userId`, `deviceId`): `Promise`\<[`DeviceRecord`](DeviceRecord.md) \| `null`\>

Get device record for a specific user's device.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`DeviceRecord`](DeviceRecord.md) \| `null`\>

***

### getDeviceSession()

> **getDeviceSession**(`userId`, `deviceId`): `Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

Get the session for a device.

#### Parameters

##### userId

`string`

##### deviceId

`number`

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

The SessionRecord, or null if no session exists.

***

### getSesameDeviceIds()

> **getSesameDeviceIds**(`userId`): `Promise`\<`number`[]\>

Get all device IDs for a specific user. The list includes the devices
whose record is marked removed. A caller that sends to the devices skips
them with `isRemovedDevice`.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`number`[]\>

***

### getUserRecord()

> **getUserRecord**(`userId`): `Promise`\<[`UserRecord`](UserRecord.md) \| `null`\>

Get user record containing all devices for a user.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<[`UserRecord`](UserRecord.md) \| `null`\>

***

### setDeviceRecord()

> **setDeviceRecord**(`userId`, `deviceId`, `record`, `options?`): `Promise`\<`void`\>

Store device record.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### record

[`DeviceRecord`](DeviceRecord.md)

##### options?

[`SetDeviceRecordOptions`](SetDeviceRecordOptions.md)

With `senderKeyHandoffInvalidation`, the same write
  deletes the sender-key handoff rows of that device in every group

#### Returns

`Promise`\<`void`\>

***

### setDeviceSession()

> **setDeviceSession**(`userId`, `deviceId`, `session`): `Promise`\<`void`\>

Set the session for a device.
This updates DeviceRecord.session.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### session

[`SessionRecord`](SessionRecord.md)

#### Returns

`Promise`\<`void`\>

***

### setUserRecord()

> **setUserRecord**(`userId`, `record`): `Promise`\<`void`\>

Store user record.

#### Parameters

##### userId

`string`

##### record

[`UserRecord`](UserRecord.md)

#### Returns

`Promise`\<`void`\>
