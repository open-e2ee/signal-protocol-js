[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / archiveCurrent

# Function: archiveCurrent()

> **archiveCurrent**(`record`, `newSession?`, `maxArchived?`): [`SessionRecord`](../../../interfaces/SessionRecord.md)

Archive the current session and optionally set a new one.

The function moves the current session to archivedSessions, keyed by its
baseKey. It trims old archived sessions if we exceed maxArchived.

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord to modify

### newSession?

[`SessionState`](../../../interfaces/SessionState.md) \| `null`

Optional new session to set as current

### maxArchived?

`number` = `MAX_ARCHIVED_SESSIONS`

Maximum number of archived sessions to keep (default: 5)

## Returns

[`SessionRecord`](../../../interfaces/SessionRecord.md)

Modified SessionRecord
