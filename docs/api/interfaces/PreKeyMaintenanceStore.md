[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreKeyMaintenanceStore

# Interface: PreKeyMaintenanceStore

App-provided persistence helpers for prekey replacement bookkeeping.

The Signal Protocol SDK owns rotation semantics; concrete storage adapters own
persistence.

## Methods

### cullReplacedOneTimePreKeys()

> **cullReplacedOneTimePreKeys**(`maxReplacedAgeMs`, `identityType?`): `Promise`\<`ReplacedOneTimePreKeyCullResult`\>

Delete replaced one-time prekeys that have exceeded the grace period.

#### Parameters

##### maxReplacedAgeMs

`number`

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`ReplacedOneTimePreKeyCullResult`\>

***

### cullReplacedPreKeys()

> **cullReplacedPreKeys**(`maxReplacedAgeMs`): `Promise`\<`ReplacedPreKeyCullResult`\>

Delete all replaced prekeys that have exceeded the grace period.

#### Parameters

##### maxReplacedAgeMs

`number`

#### Returns

`Promise`\<`ReplacedPreKeyCullResult`\>

***

### markEcOneTimePreKeysReplaced()

> **markEcOneTimePreKeysReplaced**(`identityType?`): `Promise`\<`void`\>

Mark active EC one-time prekeys as replaced before generating a fresh batch.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`void`\>

***

### markKyberOneTimePreKeysReplaced()

> **markKyberOneTimePreKeysReplaced**(`identityType?`): `Promise`\<`void`\>

Mark active Kyber one-time prekeys as replaced before generating a fresh batch.

#### Parameters

##### identityType?

[`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

#### Returns

`Promise`\<`void`\>
