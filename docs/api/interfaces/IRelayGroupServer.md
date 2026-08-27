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

> **issueProfileKeyCredential**(`userId`, `request`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Issue a profile-key credential from a blinded request for the authenticated account.

#### Parameters

##### userId

`string`

##### request

`Uint8Array`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### setUnidentifiedAccessKey()

> **setUnidentifiedAccessKey**(`userId`, `accessKey`): `Promise`\<`void`\>

Store the client-derived sealed-sender access key for the authenticated account.

#### Parameters

##### userId

`string`

##### accessKey

`Uint8Array`

#### Returns

`Promise`\<`void`\>
