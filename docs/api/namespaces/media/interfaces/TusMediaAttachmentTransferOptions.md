[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [media](../README.md) / TusMediaAttachmentTransferOptions

# Interface: TusMediaAttachmentTransferOptions

## Properties

### chunkSizeBytes?

> `optional` **chunkSizeBytes?**: `number`

***

### fetch?

> `optional` **fetch?**: \{(`input`, `init?`): `Promise`\<`Response`\>; (`input`, `init?`): `Promise`\<`Response`\>; (`input`, `init?`): `Promise`\<`Response`\>; \}

#### Call Signature

> (`input`, `init?`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

##### Parameters

###### input

`RequestInfo` \| `URL`

###### init?

`RequestInit`

##### Returns

`Promise`\<`Response`\>

#### Call Signature

> (`input`, `init?`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

##### Parameters

###### input

`RequestInfo`

###### init?

`RequestInit`

##### Returns

`Promise`\<`Response`\>

#### Call Signature

> (`input`, `init?`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

##### Parameters

###### input

`string` \| `Request` \| `URL`

###### init?

`RequestInit`

##### Returns

`Promise`\<`Response`\>

***

### tusVersion?

> `optional` **tusVersion?**: `string`
