[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceRecord

# Interface: DeviceRecord

Record of a remote device and its session.

Uses SessionRecord directly instead of a separate
SesameSessionRecord wrapper. SessionRecord.archivedSessions handles session
archiving, which eliminates the need for a separate
inactiveSessions list.

## See

https://signal.org/docs/specifications/sesame/

## Properties

### createdAt

> **createdAt**: `number`

Timestamp of the moment this device record began

***

### deviceId

> **deviceId**: `number`

Unique device identifier

***

### identityKey

> **identityKey**: `Uint8Array`

Identity public key for this device
Used for authentication and safety number generation

***

### pendingVerification?

> `optional` **pendingVerification?**: `boolean`

Whether this device's identity key requires user verification.
Set to true when identity key changes unexpectedly.
The client blocks messaging until the user verifies safety numbers.

***

### removedAt?

> `optional` **removedAt?**: `number`

The time at which the device left the device list of its user. The
removal archives the current session and keeps the record, so a message
that the device sent before its removal still decrypts. A removed device
gets no fan-out. When the device list names the device again, the
marker clears and the device returns to fan-out with no current session.
The stale-record cleanup deletes the record when the marker is older than
`SesameConfig.maxLatency`. Absent on a device that is listed.

***

### session

> **session**: [`SessionRecord`](SessionRecord.md) \| `null`

The session record for this device.

Contains:
- currentSession: Active session for sending (SessionState)
- archivedSessions: Archived sessions for receiving (indexed by baseKey)
- metadata: SESAME lifecycle info (createdAt, lastSentAt, lastReceivedAt, isInitiator)

Null if no session exists yet.

Note: Session convergence (receive-activated switching) uses
SessionRecord.promoteSession() to swap archived ↔ current.

***

### updatedAt

> **updatedAt**: `number`

Timestamp when this device record was last updated

***

### userId

> **userId**: `string`

User ID of the device owner
