[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / promoteSession

# Function: promoteSession()

> **promoteSession**(`record`, `baseKey`): `boolean`

Promote an archived session to current.

Useful when receiving a message from an old session that should
become active again (Sesame algorithm).

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord

### baseKey

[`Base64`](../../../type-aliases/Base64.md)

Base64-encoded baseKey of session to promote

## Returns

`boolean`

true if session was found and promoted
