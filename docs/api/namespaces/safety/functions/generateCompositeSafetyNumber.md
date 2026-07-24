[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / generateCompositeSafetyNumber

# Function: generateCompositeSafetyNumber()

> **generateCompositeSafetyNumber**(`localIdentity`, `remoteIdentity`, `localIdentifier`, `remoteIdentifier`, `identityType?`): [`SafetyNumber`](../interfaces/SafetyNumber.md)

Generate the composite-identity safety number from both
canonical composite identities. This is deliberately distinct from the
lower-level single-key fingerprint API.

## Parameters

### localIdentity

[`CompositeIdentityV1`](../../keys/interfaces/CompositeIdentityV1.md)

### remoteIdentity

[`CompositeIdentityV1`](../../keys/interfaces/CompositeIdentityV1.md)

### localIdentifier

`string`

### remoteIdentifier

`string`

### identityType?

[`IdentityType`](../../keys/type-aliases/IdentityType.md) = `'aci'`

## Returns

[`SafetyNumber`](../interfaces/SafetyNumber.md)
