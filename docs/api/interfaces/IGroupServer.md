[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IGroupServer

# Interface: IGroupServer

Interface for server-side group operations.

The server stores encrypted (opaque) group state and enforces
version sequencing. It never decrypts group content.

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

> **getGroup**(`groupId`, `authorization`): `Promise`\<\{ `encryptedState`: `Uint8Array`; `version`: `number`; \} \| `null`\>

Get the latest encrypted group state.

#### Parameters

##### groupId

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<\{ `encryptedState`: `Uint8Array`; `version`: `number`; \} \| `null`\>

***

### getGroupChanges()

> **getGroupChanges**(`groupId`, `fromVersion`, `authorization`): `Promise`\<`GroupChangeLogEntry`[]\>

Get change log entries from a given version.

#### Parameters

##### groupId

`Uint8Array`

##### fromVersion

`number`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<`GroupChangeLogEntry`[]\>

***

### submitGroupChange()

> **submitGroupChange**(`groupId`, `expectedVersion`, `encryptedChange`, `updatedEncryptedState`, `authorization`): `Promise`\<\{ `serverSignature`: `Uint8Array`; \}\>

Submit a group change (optimistic concurrency).

#### Parameters

##### groupId

`Uint8Array`

##### expectedVersion

`number`

##### encryptedChange

`Uint8Array`

##### updatedEncryptedState

`Uint8Array`

##### authorization

[`GroupAuthorization`](GroupAuthorization.md)

#### Returns

`Promise`\<\{ `serverSignature`: `Uint8Array`; \}\>
