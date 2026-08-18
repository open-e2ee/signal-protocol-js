[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / BlockedRecipientEntry

# Interface: BlockedRecipientEntry

Signal Protocol blocking contracts.

Blocking is account/contact state, not message content. The core package owns
the local blocking workflow. Each app chooses whether blocked state is purely
local, linked-device synced, mirrored to a backend, or all three.

## Properties

### blockedAt

> **blockedAt**: `number`

***

### recipientId

> **recipientId**: `string`
