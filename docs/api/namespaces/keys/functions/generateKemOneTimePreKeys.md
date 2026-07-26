[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateKemOneTimePreKeys

# Function: generateKemOneTimePreKeys()

> **generateKemOneTimePreKeys**(`identityKeyPair`, `count`, `startId?`): `Promise`\<[`KemOneTimePreKey`](../interfaces/KemOneTimePreKey.md)[]\>

Generate batch of KEM one-time prekeys (post-quantum)

Creates multiple one-time Kyber prekeys for PQXDH.
Each key can only be used once for per-session post-quantum forward secrecy.

Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys
that the server prefers over the last-resort KEM prekey.

Uses the same batch size as EC one-time prekeys (the reference implementation uses 100 for both).

## Parameters

### identityKeyPair

[`IdentityKeyPair`](../../../interfaces/IdentityKeyPair.md)

Complete composite identity key pair for contextual signing

### count

`number`

Number of prekeys to generate

### startId?

`number` = `0`

Starting ID for sequential assignment

## Returns

`Promise`\<[`KemOneTimePreKey`](../interfaces/KemOneTimePreKey.md)[]\>

## See

https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message
