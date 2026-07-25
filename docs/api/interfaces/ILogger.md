[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ILogger

# Interface: ILogger

Signal Protocol package logging primitives.

The package resolves a logger once at composition time and passes it through
explicit dependencies. This keeps logging package-local without relying on
mutable module-global state.

## Methods

### breadcrumb()?

> `optional` **breadcrumb**(`message`, `data?`): `void`

#### Parameters

##### message

`string`

##### data?

`unknown`

#### Returns

`void`

***

### debug()?

> `optional` **debug**(`message`, `data?`): `void`

#### Parameters

##### message

`string`

##### data?

`unknown`

#### Returns

`void`

***

### error()?

> `optional` **error**(`message`, `errorOrData?`, `data?`): `void`

#### Parameters

##### message

`string`

##### errorOrData?

`unknown`

##### data?

`unknown`

#### Returns

`void`

***

### info()?

> `optional` **info**(`message`, `data?`): `void`

#### Parameters

##### message

`string`

##### data?

`unknown`

#### Returns

`void`

***

### warn()?

> `optional` **warn**(`message`, `data?`): `void`

#### Parameters

##### message

`string`

##### data?

`unknown`

#### Returns

`void`
