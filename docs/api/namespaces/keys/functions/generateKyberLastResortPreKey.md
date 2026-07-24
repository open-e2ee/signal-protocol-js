[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateKyberLastResortPreKey

# Function: generateKyberLastResortPreKey()

> **generateKyberLastResortPreKey**(`identityKeyPair`, `id?`): `Promise`\<[`KyberPreKey`](../../../interfaces/KyberPreKey.md)\>

Generate Kyber prekey for PQXDH

Creates a post-quantum prekey using ML-KEM-1024 (Kyber).
Per PQXDH spec Section 3.2, this is a "signed last-resort" prekey
that rotates periodically, always using ID 1.

## Parameters

### identityKeyPair

[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)

Complete composite identity key pair for contextual signing

### id?

`number` = `1`

Optional prekey ID (default: 1 per PQXDH spec)

## Returns

`Promise`\<[`KyberPreKey`](../../../interfaces/KyberPreKey.md)\>

## See

https://signal.org/docs/specifications/pqxdh/
