[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IRelayGroupServer

# Interface: IRelayGroupServer

Optional relay capability for the Group System.

The trust root is intentionally absent: clients pin it out of band rather
than discovering and trusting it from this runtime capability.

## Properties

### server

> `readonly` **server**: [`IGroupServer`](IGroupServer.md)

Encrypted group-state transport.

## Methods

### issueAuthCredential()

> **issueAuthCredential**(`userId`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Issue an auth credential for the relay's authenticated account.

#### Parameters

##### userId

`string`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### issueProfileKeyCredential()

> **issueProfileKeyCredential**(`userId`, `profileKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Issue a profile-key credential for the relay's authenticated account.

#### Parameters

##### userId

`string`

##### profileKey

`Uint8Array`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>
