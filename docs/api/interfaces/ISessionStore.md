[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISessionStore

# Interface: ISessionStore

Session store for current package session records.

Manages Double Ratchet session state with support for session archiving
and the Sesame algorithm for session convergence.

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

### archiveCurrentSession()

> **archiveCurrentSession**(`address`, `newSession?`): `Promise`\<`void`\>

Archive the current session and optionally start a new one.

Used when:
- Identity key changes (possible MITM)
- Registration ID changes (app reinstall detected)
- Manual session reset

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

##### newSession?

[`SessionState`](SessionState.md) \| `null`

Optional new session to set as current

#### Returns

`Promise`\<`void`\>

***

### deleteSessionRecord()

> **deleteSessionRecord**(`address`): `Promise`\<`void`\>

Delete session record.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<`void`\>

***

### getSessionCount()

> **getSessionCount**(): `Promise`\<`number`\>

Get the count of active sessions.

#### Returns

`Promise`\<`number`\>

Number of sessions stored

***

### getSessionRecord()

> **getSessionRecord**(`address`): `Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

Retrieve session record.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md) \| `null`\>

SessionRecord or null if no session exists

***

### getSessionsForUser()

> **getSessionsForUser**(`userId`): `Promise`\<[`SessionRecord`](SessionRecord.md)[]\>

Get all sessions for a user (across all their devices).

Useful for multi-device scenarios where one user has multiple devices.

#### Parameters

##### userId

`string`

User ID (not including device ID)

#### Returns

`Promise`\<[`SessionRecord`](SessionRecord.md)[]\>

Array of session records for all of this user's devices

***

### hasSession()

> **hasSession**(`address`): `Promise`\<`boolean`\>

Check if a session exists for the given address.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address

#### Returns

`Promise`\<`boolean`\>

true if session exists

***

### storeSessionRecord()

> **storeSessionRecord**(`address`, `record`): `Promise`\<`void`\>

Store session record with current + archived sessions.

This is the preferred API for session storage, supporting session archiving
and handling race conditions.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Protocol address for this session

##### record

[`SessionRecord`](SessionRecord.md)

SessionRecord containing current and archived sessions

#### Returns

`Promise`\<`void`\>
