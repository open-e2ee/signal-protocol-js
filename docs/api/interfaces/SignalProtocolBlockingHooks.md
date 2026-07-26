[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolBlockingHooks

# Interface: SignalProtocolBlockingHooks

Optional local side effects that belong to the act of blocking itself.

Example:
- Rotate the local profile key after a recipient loses profile access

## Methods

### onRecipientBlocked()?

> `optional` **onRecipientBlocked**(`entry`): `Promise`\<`void`\>

#### Parameters

##### entry

[`BlockedRecipientEntry`](BlockedRecipientEntry.md)

#### Returns

`Promise`\<`void`\>

***

### onRecipientUnblocked()?

> `optional` **onRecipientUnblocked**(`recipientId`): `Promise`\<`void`\>

#### Parameters

##### recipientId

`string`

#### Returns

`Promise`\<`void`\>
