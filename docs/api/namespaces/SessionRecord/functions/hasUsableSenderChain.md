[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [SessionRecord](../README.md) / hasUsableSenderChain

# Function: hasUsableSenderChain()

> **hasUsableSenderChain**(`record`, `now?`): `boolean`

Check if the session has a usable sender chain for encrypting messages.

A session is usable for sending if:
1. It has a current session
2. The current session has sending chain keys (CKs)
3. The session hasn't expired for sending (per SESAME MAXSEND threshold)

## Parameters

### record

[`SessionRecord`](../../../interfaces/SessionRecord.md)

SessionRecord to check

### now?

`number` = `...`

Current time (default: Date.now())

## Returns

`boolean`

true if session can be used for sending
