[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / archiveCurrentState

# Function: archiveCurrentState()

> **archiveCurrentState**(`record`): [`SessionRecord`](../../../interfaces/SessionRecord.md)

Archive the current session state when receiving a new PreKeyMessage.

- Move the current session to archived (if it exists)
- Clear the current session slot
- A separate step sets the new session from PreKeyMessage

Called when:
- Receiving a PreKeyMessage from a device we already have a session with
- Identity key changes (possible MITM - archive for later decryption)
- Registration ID changes (device reinstall detected)

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord to modify

## Returns

[`SessionRecord`](../../../interfaces/SessionRecord.md)

Modified SessionRecord with current session archived
