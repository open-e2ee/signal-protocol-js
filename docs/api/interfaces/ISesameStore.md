[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISesameStore

# Interface: ISesameStore

SESAME store interface for multi-device session management.

Implements the SESAME algorithm for automatic session convergence
across multiple devices.

Session state is stored directly on each `DeviceRecord`.

## See

https://signal.org/docs/specifications/sesame/

## Extended by

- [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md)

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

Delete device record.

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

Delete stale device records (orphaned sessions older than MAXLATENCY).

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

Get all device IDs for a specific user.

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

> **setDeviceRecord**(`userId`, `deviceId`, `record`): `Promise`\<`void`\>

Store device record.

#### Parameters

##### userId

`string`

##### deviceId

`number`

##### record

[`DeviceRecord`](DeviceRecord.md)

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
