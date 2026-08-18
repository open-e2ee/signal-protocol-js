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
