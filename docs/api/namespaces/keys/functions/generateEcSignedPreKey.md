[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateEcSignedPreKey

# Function: generateEcSignedPreKey()

> **generateEcSignedPreKey**(`identityKeyPair`, `id?`): `Promise`\<[`EcSignedPreKey`](../../../interfaces/EcSignedPreKey.md)\>

Generate EC signed prekey

Creates an EC signed prekey that includes:
- ECDH key pair for key agreement
- Signature over public key using identity signing key
- Timestamp for rotation tracking

## Parameters

### identityKeyPair

[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)

Complete composite identity key pair for contextual signing

### id?

`number`

Optional prekey ID (random if not provided)

## Returns

`Promise`\<[`EcSignedPreKey`](../../../interfaces/EcSignedPreKey.md)\>

## See

 - https://signal.org/docs/specifications/x3dh/#keys
 - https://signal.org/docs/specifications/x3dh/#publishing-keys
