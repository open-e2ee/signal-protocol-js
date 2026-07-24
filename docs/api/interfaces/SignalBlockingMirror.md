[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalBlockingMirror

# Interface: SignalBlockingMirror

Optional app/backend mirror for local block changes.

Examples:
- Linked-device blocklist snapshot sync
- A platform projection into another local runtime (for example, an NSE cache)
- No-op for a fully local-only app

## Methods

### syncBlockedRecipients()

> **syncBlockedRecipients**(`entries`): `Promise`\<`void`\>

#### Parameters

##### entries

readonly [`BlockedRecipientEntry`](BlockedRecipientEntry.md)[]

#### Returns

`Promise`\<`void`\>
