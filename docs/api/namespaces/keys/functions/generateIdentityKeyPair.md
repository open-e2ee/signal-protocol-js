[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateIdentityKeyPair

# Function: generateIdentityKeyPair()

> **generateIdentityKeyPair**(): `Promise`\<[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)\>

Generate identity key pair

Creates the long-lived identity key pair consisting of:
- DH key pair for X3DH/PQXDH key agreement
- Signing key pair for prekey signatures
- Registration ID for session reset detection

## Returns

`Promise`\<[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)\>

## See

https://signal.org/docs/specifications/x3dh/#keys
