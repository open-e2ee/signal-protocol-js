[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionRecord

# Interface: SessionRecord

Session record wrapper for session archiving and versioning.

Provides SessionRecord which supports the Sesame algorithm
for automatic session convergence. Maintains current session plus archived
sessions for handling race conditions and out-of-order establishment.

From Signal Protocol:
"A device might have multiple sessions for the same remote device.
The Sesame algorithm ensures convergence to a single active session."

Session Lookup Architecture:
1. Sessions are LOOKED UP by ProtocolAddress (userId:deviceId)
2. Within a SessionRecord, session states are IDENTIFIED by baseKey
3. The baseKey is the initiator's ephemeral public key from X3DH/PQXDH

## See

https://signal.org/docs/specifications/sesame/

## Properties

### archivedSessions

> **archivedSessions**: `Record`\<[`Base64`](../type-aliases/Base64.md), [`SessionState`](SessionState.md)\>

Archived sessions indexed by baseKey for O(1) lookup.

Session states are identified by the initiator's ephemeral public key
(`baseKey`).

Used for:
- Handling race conditions during session establishment
- Decrypting messages from old sessions
- Implementing Sesame algorithm for session convergence

Key: Base64-encoded baseKey (initiator's ephemeral public key)
Value: SessionState

Session records are keyed by baseKey for fast lookup and spec-aligned
session recovery behavior.

***

### currentSession

> **currentSession**: [`SessionState`](SessionState.md) \| `null`

Current active session state.

This is the session used for encrypting new messages.
May be null if all sessions have been archived (rare edge case).

***

### metadata?

> `optional` **metadata?**: [`SessionRecordMetadata`](SessionRecordMetadata.md)

Metadata about the session record.

Useful for UI, logging, and session management.

***

### version

> **version**: `4`

Protocol version for this persisted session record shape.

The current format is version 4. Older versions are rejected and force
session re-establishment instead of compatibility migration.
