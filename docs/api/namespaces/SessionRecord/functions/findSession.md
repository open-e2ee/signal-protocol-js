[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / findSession

# Function: findSession()

> **findSession**(`record`, `baseKey`): [`SessionState`](../../../interfaces/SessionState.md) \| `null`

Find a session by baseKey.

Session states are identified by the initiator's ephemeral public key
(`baseKey`).

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord

### baseKey

[`Base64`](../../../type-aliases/Base64.md)

Base64-encoded baseKey to find

## Returns

[`SessionState`](../../../interfaces/SessionState.md) \| `null`

SessionState if found, null otherwise
