[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IEcSignedPreKeyStore

# Interface: IEcSignedPreKeyStore

EC Signed PreKey store with an SDK-oriented API.

Manages rotating EC signed prekeys for medium-term forward secrecy.
The client rotates EC signed prekeys on the configured refresh interval
(2 days by default). The store must keep OLD prekeys for a grace period
(~30 days) to handle in-flight messages.

Per X3DH Spec Section 4.4:

> "After uploading a new signed prekey, Bob may keep the private key
> corresponding to the previous signed prekey around for some period
> of time, to handle messages using it that have been delayed in transit."

## See

https://signal.org/docs/specifications/x3dh/

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

### getAllEcSignedPreKeys()?

> `optional` **getAllEcSignedPreKeys**(`identityType?`): `Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md)[]\>

Get all stored EC signed prekeys (current + archived).

Used for cleanup and debugging.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md)[]\>

***

### getEcSignedPreKey()

> **getEcSignedPreKey**(`keyId?`, `identityType?`): `Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md) \| `null`\>

Retrieve EC signed prekey by ID.

#### Parameters

##### keyId?

`number`

Optional key ID to retrieve. If not provided, returns the current (most recent) EC signed prekey.

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`EcSignedPreKey`](EcSignedPreKey.md) \| `null`\>

The EC signed prekey, or null if not found

***

### removeEcSignedPreKey()?

> `optional` **removeEcSignedPreKey**(`keyId`, `identityType?`): `Promise`\<`void`\>

Remove an EC signed prekey by ID.

Called during cleanup to remove expired archived prekeys.
Should NEVER remove the current (most recent) EC signed prekey.

#### Parameters

##### keyId

`number`

The key ID to remove

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### storeEcSignedPreKey()

> **storeEcSignedPreKey**(`signedPreKey`, `identityType?`): `Promise`\<`void`\>

Store EC signed prekey.

When storing a new EC signed prekey (rotation), archive the old one
instead of deleting it, to handle in-flight messages.

#### Parameters

##### signedPreKey

[`EcSignedPreKey`](EcSignedPreKey.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>
