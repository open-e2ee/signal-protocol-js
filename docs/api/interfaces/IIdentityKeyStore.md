[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IIdentityKeyStore

# Interface: IIdentityKeyStore

Identity store with an SDK-oriented API and SDK composite-identity values.

Manages local identity keys and contact identity verification. TOFU detects
changes after a tuple is pinned; it does not authenticate first contact.

## Extended by

- [`IProtocolStore`](IProtocolStore.md)

## Methods

### acceptContactIdentityRotation()

> **acceptContactIdentityRotation**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Explicitly accept a changed tuple and atomically delete every session for
that user; the previous tuple becomes rollback history.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

***

### getContactIdentity()

> **getContactIdentity**(`address`, `identityType?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md) \| `null`\>

Get a contact's saved identity key.

Returns null if no identity key has been saved for this address.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md) \| `null`\>

Contact's identity key or null

***

### getIdentityKey()

> **getIdentityKey**(`identityType?`): `Promise`\<[`IdentityKeyPair`](IdentityKeyPair.md) \| `null`\>

Retrieve our identity key pair.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<[`IdentityKeyPair`](IdentityKeyPair.md) \| `null`\>

***

### getLocalRegistrationId()

> **getLocalRegistrationId**(`identityType?`): `Promise`\<`number`\>

Get our local registration ID.

Registration ID is a random 16-bit integer generated once per install.
Used to detect session resets when app is reinstalled.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`number`\>

***

### hasIdentityKey()

> **hasIdentityKey**(`identityType?`): `Promise`\<`boolean`\>

Check if identity key exists.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`boolean`\>

***

### isTrustedIdentity()

> **isTrustedIdentity**(`address`, `identity`, `direction`, `identityType?`): `Promise`\<`boolean`\>

Check if a contact's identity key is trusted.

Trust verification behavior depends on direction:
- SENDING: Stricter - don't send to untrusted identities
- RECEIVING: More permissive - allow receiving but warn user

From Signal Protocol:
"It's safer to receive from an unknown identity than to send to one"

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Complete composite identity candidate

##### direction

[`TrustDirection`](../enumerations/TrustDirection.md)

Whether we're sending or receiving

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

ACI or PNI trust namespace

#### Returns

`Promise`\<`boolean`\>

true if identity is trusted

***

### saveContactIdentity()

> **saveContactIdentity**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`IdentityKeyChange`](../enumerations/IdentityKeyChange.md)\>

Save a contact's identity key and detect changes.

This is used for Trust On First Use (TOFU) and post-pinning change
detection. Returns whether either composite component changed.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

Contact's protocol address

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Contact's complete canonical composite identity

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

ACI or PNI trust namespace

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

Optional redundant commitment that must match

#### Returns

`Promise`\<[`IdentityKeyChange`](../enumerations/IdentityKeyChange.md)\>

IdentityKeyChange indicating if key is new or changed

***

### setLocalRegistrationId()

> **setLocalRegistrationId**(`id`, `identityType?`): `Promise`\<`void`\>

Set our local registration ID.

Should only be called once during initialization.

#### Parameters

##### id

`number`

Registration ID

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### storeIdentityKey()

> **storeIdentityKey**(`keyPair`, `identityType?`): `Promise`\<`void`\>

Store our identity key pair (only done once per install per identity type).

#### Parameters

##### keyPair

[`IdentityKeyPair`](IdentityKeyPair.md)

Identity key pair to store

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

'aci' or 'pni' (defaults to 'aci')

#### Returns

`Promise`\<`void`\>

***

### verifyContactIdentity()

> **verifyContactIdentity**(`address`, `identity`, `identityType?`, `suppliedCommitment?`): `Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>

Promote the exact current tuple after authenticated comparison.

#### Parameters

##### address

[`ProtocolAddress`](ProtocolAddress.md)

##### identity

[`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

##### suppliedCommitment?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`ContactIdentityRecord`](../namespaces/keys/interfaces/ContactIdentityRecord.md)\>
