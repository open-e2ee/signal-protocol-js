[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayPresence

# Interface: HostedRelayPresence

The presence of a hosted client with a mailbox subscription. Each request
needs a connected socket and otherwise fails with `NOT_CONNECTED`.

## Methods

### accessKey()

> **accessKey**(`profileKey`): `Promise`\<`string`\>

Derives this account's presence key from its 32-byte profile key,
registers the key with the Relay, and returns it. A new profile key
revokes every old holder. With `hosted.profileKeys`, the SDK calls it
when the profile key changes.

#### Parameters

##### profileKey

`Uint8Array`

#### Returns

`Promise`\<`string`\>

***

### grant()

> **grant**(`account`, `presenceKey`): `Promise`\<`void`\>

Stores the presence key that a contact sent, for later reads. With
`hosted.profileKeys`, the SDK calls it for each contact profile key that
it receives.

#### Parameters

##### account

`string`

##### presenceKey

`string`

#### Returns

`Promise`\<`void`\>

***

### policy()

> **policy**(): `Promise`\<[`HostedRelayPresencePolicy`](HostedRelayPresencePolicy.md)\>

The project's presence policy, so the app can show or disable its toggle.

#### Returns

`Promise`\<[`HostedRelayPresencePolicy`](HostedRelayPresencePolicy.md)\>

***

### read()

> **read**(`accounts`): `Promise`\<([`HostedRelayPresenceStatus`](HostedRelayPresenceStatus.md) \| `null`)[]\>

Reads the presence of each account, in the order given. A null result is
the same for a hidden account, an unknown account, a missing or wrong
key, and a project with presence off. The read sends the key that
`grant()` stored for each account.

#### Parameters

##### accounts

readonly `string`[]

#### Returns

`Promise`\<([`HostedRelayPresenceStatus`](HostedRelayPresenceStatus.md) \| `null`)[]\>

***

### setting()

> **setting**(): `Promise`\<[`HostedRelayPresenceAccount`](HostedRelayPresenceAccount.md)\>

The local account's setting and the visibility that applies.

#### Returns

`Promise`\<[`HostedRelayPresenceAccount`](HostedRelayPresenceAccount.md)\>

***

### setVisibility()

> **setVisibility**(`visibility`): `Promise`\<[`HostedRelayPresenceAccount`](HostedRelayPresenceAccount.md)\>

Writes the local account's setting. It fails with
`PRESENCE_SETTING_FORCED` under the `forced` mode and with
`INVALID_TRANSITION` under the `off` mode.

#### Parameters

##### visibility

[`HostedRelayPresenceVisibility`](../type-aliases/HostedRelayPresenceVisibility.md)

#### Returns

`Promise`\<[`HostedRelayPresenceAccount`](HostedRelayPresenceAccount.md)\>

***

### watch()

> **watch**(`account`, `onChange`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Calls `onChange` with the account's presence, then again after each
change. It reads every 30 s while the mailbox socket is connected, and at
once when the socket connects. A failed read keeps the last value. After
a `FRAME_REJECTED` read, it waits 30 s after the reconnect.

#### Parameters

##### account

`string`

##### onChange

(`status`) => `void`

#### Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)
