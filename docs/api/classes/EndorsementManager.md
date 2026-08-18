[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / EndorsementManager

# Class: EndorsementManager

## Constructors

### Constructor

> **new EndorsementManager**(`cache`, `endorsementRootPublicKey`, `logger?`): `EndorsementManager`

#### Parameters

##### cache

`EndorsementCacheStore`

##### endorsementRootPublicKey

[`ServerRootPublicKey`](ServerRootPublicKey.md)

##### logger?

`Required`\<[`ILogger`](../interfaces/ILogger.md)\> = `defaultSignalProtocolLogger`

#### Returns

`EndorsementManager`

## Methods

### assertEndorsementRootPublicKey()

> **assertEndorsementRootPublicKey**(`expected`): `void`

Require this verifier to use the endorsement root pinned by group config.

#### Parameters

##### expected

[`ServerRootPublicKey`](ServerRootPublicKey.md)

#### Returns

`void`

***

### clearGroupEndorsements()

> **clearGroupEndorsements**(`groupId`): `Promise`\<`void`\>

Clear cached endorsements for a group.

Call on membership changes (member added/removed) to force
re-issuance on next group send.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`void`\>

***

### getCachedExpiration()

> **getCachedExpiration**(`groupId`): `Promise`\<`number` \| `null`\>

Get the cached endorsement expiration for a group.

#### Parameters

##### groupId

`string`

#### Returns

`Promise`\<`number` \| `null`\>

Expiration in epoch seconds, or null if no cache exists

***

### getCombinedToken()

> **getCombinedToken**(`groupId`, `recipientUserIds`, `groupSecretParams?`): `Promise`\<\{ `aciBytesByUserId`: `Map`\<`string`, `Uint8Array`\<`ArrayBufferLike`\>\>; `expiration`: `number`; `token`: `Uint8Array`; \} \| `null`\>

Get a combined token for multi-recipient (Sender Key) sends.

Combines individual endorsements for all specified recipients into
a single token. This is the algebraic set-union operation on
endorsement points before unblinding and hashing.

#### Parameters

##### groupId

`string`

Group identifier

##### recipientUserIds

`string`[]

User IDs of all recipients (excluding self)

##### groupSecretParams?

`GroupSecretParams`

#### Returns

`Promise`\<\{ `aciBytesByUserId`: `Map`\<`string`, `Uint8Array`\<`ArrayBufferLike`\>\>; `expiration`: `number`; `token`: `Uint8Array`; \} \| `null`\>

Serialized 24-byte full token and expiration, or null if unavailable

***

### getTokenForRecipient()

> **getTokenForRecipient**(`groupId`, `recipientUserId`, `groupSecretParams?`): `Promise`\<\{ `aciBytes`: `Uint8Array`; `expiration`: `number`; `token`: `Uint8Array`; \} \| `null`\>

Get a serialized GroupSendFullToken for a single recipient.

Decompresses the cached endorsement, unblinds it with the group's
UID encryption key, and produces a 24-byte token suitable for
sending via the relay.

#### Parameters

##### groupId

`string`

Group identifier

##### recipientUserId

`string`

User ID of the recipient (used as cache key)

##### groupSecretParams?

`GroupSecretParams`

#### Returns

`Promise`\<\{ `aciBytes`: `Uint8Array`; `expiration`: `number`; `token`: `Uint8Array`; \} \| `null`\>

Serialized 24-byte full token and expiration, or null if unavailable

***

### isExpired()

> **isExpired**(`expiration`): `boolean`

Check whether cached endorsements expired.

#### Parameters

##### expiration

`number`

Cached endorsement expiration in epoch seconds

#### Returns

`boolean`

true if endorsements are past expiration

***

### isMissingAnyEndorsements()

> **isMissingAnyEndorsements**(`groupId`, `memberUserIds`): `Promise`\<`boolean`\>

Check whether any group member lacks a cached endorsement.

Used in the pre-send endorsement refresh check.

#### Parameters

##### groupId

`string`

Group identifier

##### memberUserIds

`string`[]

User IDs of all group members (excluding self)

#### Returns

`Promise`\<`boolean`\>

true if any member lacks one, false if all present or no cache

***

### needsRefresh()

> **needsRefresh**(`expiration`): `boolean`

Check if cached endorsements need refresh.

#### Parameters

##### expiration

`number`

Cached endorsement expiration in epoch seconds

#### Returns

`boolean`

true if endorsements expire within 2 hours

***

### processAndCacheEndorsements()

> **processAndCacheEndorsements**(`groupId`, `endorsementsResponseBytes`, `memberServiceIds`, `memberUserIds`, `localUserId`, `groupSecretParams`): `Promise`\<`void`\>

Process an endorsement response from the server, validate the batch
proof, and cache per-member endorsements to SQLite.

The caller is responsible for fetching the response via the
`refreshGroupSendEndorsements` mutation.

#### Parameters

##### groupId

`string`

Group identifier for cache key

##### endorsementsResponseBytes

`Uint8Array`

Serialized GroupSendEndorsementsResponse from server

##### memberServiceIds

[`ServiceId`](../interfaces/ServiceId.md)[]

ServiceIds of all group members (must match server order)

##### memberUserIds

`string`[]

Convex user IDs parallel to memberServiceIds (used as cache keys)

##### localUserId

`string`

Self user ID to exclude from the cache

##### groupSecretParams

`GroupSecretParams`

#### Returns

`Promise`\<`void`\>

#### Throws

VerificationFailure if batch proof validation fails

***

### shouldRefreshEndorsements()

> **shouldRefreshEndorsements**(`groupId`, `memberUserIds`): `Promise`\<\{ `needsRefresh`: `boolean`; `reason?`: `"missing_cache"` \| `"expiring_soon"` \| `"missing_members"`; \}\>

Check whether endorsements need a refresh before sending.

Checks three conditions:
 1. No endorsements cached at all
 2. Endorsements expire within 2 hours
 3. Any group member lacks an endorsement

#### Parameters

##### groupId

`string`

Group identifier

##### memberUserIds

`string`[]

User IDs of all group members (excluding self)

#### Returns

`Promise`\<\{ `needsRefresh`: `boolean`; `reason?`: `"missing_cache"` \| `"expiring_soon"` \| `"missing_members"`; \}\>

Object indicating whether a refresh applies, and why
