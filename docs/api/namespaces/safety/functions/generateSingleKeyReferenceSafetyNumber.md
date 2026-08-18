[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / generateSingleKeyReferenceSafetyNumber

# Function: generateSingleKeyReferenceSafetyNumber()

> **generateSingleKeyReferenceSafetyNumber**(`user1IdentityKey`, `user2IdentityKey`, `user1Identifier`, `user2Identifier`): [`SafetyNumber`](../interfaces/SafetyNumber.md)

Generate a reference single-key fingerprint for two users.

This low-level primitive does not authenticate the package's complete
X25519 + Ed25519 composite identity. Callers MUST NOT use it for contact identity
verification. Applications must use SignalProtocolClient.verify(), or the explicitly
composite generateCompositeSafetyNumber() helper.

Uses SHA-512 iteration with 5,200 iterations per Signal Protocol spec.
The function caches results for performance, because the iteration costs a
lot of computation.

## Parameters

### user1IdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

User 1's identity public key (PublicKey branded type)

### user2IdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

User 2's identity public key (PublicKey branded type)

### user1Identifier

`string`

User 1's identifier (e.g., username or ID)

### user2Identifier

`string`

User 2's identifier

## Returns

[`SafetyNumber`](../interfaces/SafetyNumber.md)

Safety number in multiple formats
