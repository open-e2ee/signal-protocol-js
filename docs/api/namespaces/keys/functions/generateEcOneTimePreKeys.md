[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateEcOneTimePreKeys

# Function: generateEcOneTimePreKeys()

> **generateEcOneTimePreKeys**(`count`, `startId?`): `Promise`\<[`EcOneTimePreKey`](../../../interfaces/EcOneTimePreKey.md)[]\>

Generate batch of EC one-time prekeys

Creates multiple EC one-time prekeys for X3DH.
Each key serves only one use, for forward secrecy.

## Parameters

### count

`number`

Number of prekeys to generate

### startId?

`number` = `0`

Starting ID for sequential assignment

## Returns

`Promise`\<[`EcOneTimePreKey`](../../../interfaces/EcOneTimePreKey.md)[]\>

## See

 - https://signal.org/docs/specifications/x3dh/#keys
 - https://signal.org/docs/specifications/x3dh/#publishing-keys
