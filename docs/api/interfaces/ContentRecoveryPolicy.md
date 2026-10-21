[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ContentRecoveryPolicy

# Interface: ContentRecoveryPolicy

The content recovery policy of a client.

## Properties

### isCurrentMember?

> `optional` **isCurrentMember?**: (`groupId`, `userId`) => `Promise`\<`boolean`\>

Answer whether a user is a current member of an ad hoc group. The
sender asks it before it gives logged group content to a device again.
A managed group is checked against its verified group state instead.
The hook gets the prefixed group ID that `createGroupId` makes. Without
this hook, the sender gives no content again for an ad hoc group.
`contentRecoveryStatus.groupMembershipSource` names the source that the
client has.

#### Parameters

##### groupId

`string`

##### userId

`string`

#### Returns

`Promise`\<`boolean`\>

***

### mode?

> `optional` **mode?**: [`ContentRecoveryMode`](../type-aliases/ContentRecoveryMode.md)

#### Default

```ts
'require-protected'
```

***

### retentionMs?

> `optional` **retentionMs?**: `number`

How long the sender keeps resendable content, in milliseconds, from the
time it first stored the content. A retry does not extend it. The value
must be a positive integer of at most 30 days.

#### Default

```ts
1209600000 (14 days)
```
