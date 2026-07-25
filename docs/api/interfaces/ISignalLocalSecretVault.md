[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ISignalLocalSecretVault

# Interface: ISignalLocalSecretVault

Small local secret vault used to bootstrap a local Signal Protocol store.

This interface is intentionally narrow: it exists for secrets that must
remain outside the main local store, such as a database encryption key.
It is not a second general-purpose Signal Protocol data store.

## Methods

### deleteSecret()

> **deleteSecret**(`name`): `Promise`\<`void`\>

Delete a named secret from local secure storage.

#### Parameters

##### name

`string`

#### Returns

`Promise`\<`void`\>

***

### getSecret()

> **getSecret**(`name`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Read a named secret from local secure storage.

#### Parameters

##### name

`string`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

***

### setSecret()

> **setSecret**(`name`, `value`): `Promise`\<`void`\>

Persist a named secret to local secure storage.

#### Parameters

##### name

`string`

##### value

`Uint8Array`

#### Returns

`Promise`\<`void`\>
