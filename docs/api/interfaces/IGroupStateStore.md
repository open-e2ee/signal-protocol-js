[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IGroupStateStore

# Interface: IGroupStateStore

Interface for local group state storage.

Stores master keys (the root secret for each group) and decrypted state
cache for offline access.

## Methods

### deleteGroupState()

> **deleteGroupState**(`groupId`): `Promise`\<`void`\>

Delete cached group state.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`void`\>

***

### deleteMasterKey()

> **deleteMasterKey**(`groupId`): `Promise`\<`void`\>

Delete a group master key.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`void`\>

***

### getGroupState()

> **getGroupState**(`groupId`): `Promise`\<[`DecryptedGroup`](DecryptedGroup.md) \| `null`\>

Get cached decrypted group state.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<[`DecryptedGroup`](DecryptedGroup.md) \| `null`\>

***

### getMasterKey()

> **getMasterKey**(`groupId`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Get a group master key.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

***

### storeGroupState()

> **storeGroupState**(`groupId`, `state`): `Promise`\<`void`\>

Store decrypted group state cache.

#### Parameters

##### groupId

`string`

##### state

[`DecryptedGroup`](DecryptedGroup.md)

#### Returns

`Promise`\<`void`\>

***

### storeMasterKey()

> **storeMasterKey**(`groupId`, `masterKey`): `Promise`\<`void`\>

Store a group master key.

#### Parameters

##### groupId

`string`

##### masterKey

`Uint8Array`

#### Returns

`Promise`\<`void`\>
