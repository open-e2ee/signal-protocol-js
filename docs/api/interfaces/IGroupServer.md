[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IGroupServer

# Interface: IGroupServer

Interface for server-side group operations.

The server stores encrypted group state, verifies presentations, evaluates
policy through deterministic ciphertext comparison, and enforces version
sequencing. It never decrypts group content.

## Methods

### createGroup()

> **createGroup**(`groupId`, `encryptedState`, `authorization`): `Promise`\<`void`\>

Create a new group on the server.

#### Parameters

##### groupId

`Uint8Array`

##### encryptedState

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<`void`\>

***

### getGroup()

> **getGroup**(`groupId`, `authorization`, `version?`): `Promise`\<[`GroupSnapshot`](GroupSnapshot.md) \| `null`\>

Get encrypted group state.

When `version` is supplied, the server must return that exact historical
snapshot or null. Versioned reads make the post-join baseline race-safe:
clients must not jump over unverified changes to a newer snapshot.

#### Parameters

##### groupId

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

##### version?

`number`

#### Returns

`Promise`\<[`GroupSnapshot`](GroupSnapshot.md) \| `null`\>

***

### getGroupChanges()

> **getGroupChanges**(`groupId`, `fromVersion`, `authorization`): `Promise`\<`GroupChangeLogPage`\>

Get one page of the authorized change log after a historical version.

Authorization is evaluated at the `fromVersion` snapshot, and the
requester must be a member there (S10; S10a governs how a refused
pending requester advances instead). The page includes the first
transition whose post-state drops the requester from `members`, then
stops; a requester who is not a member at that snapshot is refused.
`hasMore` signals a page cut for size, resumable from the last served
version.

#### Parameters

##### groupId

`Uint8Array`

##### fromVersion

`number`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<`GroupChangeLogPage`\>

***

### getGroupJoinInfo()

> **getGroupJoinInfo**(`groupId`, `inviteLinkPassword`, `authorization`): `Promise`\<\{ `encryptedJoinInfo`: `Uint8Array`; `version`: `number`; \} \| `null`\>

Get the reduced invite-link projection after server-side password verification.

#### Parameters

##### groupId

`Uint8Array`

##### inviteLinkPassword

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<\{ `encryptedJoinInfo`: `Uint8Array`; `version`: `number`; \} \| `null`\>

***

### submitGroupChange()

> **submitGroupChange**(`groupId`, `expectedVersion`, `actions`, `inviteLinkPassword`, `authorization`): `Promise`\<`GroupChangeLogEntry`\>

Submit a group change (optimistic concurrency).

#### Parameters

##### groupId

`Uint8Array`

##### expectedVersion

`number`

##### actions

`Uint8Array`

##### inviteLinkPassword

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<`GroupChangeLogEntry`\>
