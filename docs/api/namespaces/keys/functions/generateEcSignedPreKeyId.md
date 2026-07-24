[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / generateEcSignedPreKeyId

# Function: generateEcSignedPreKeyId()

> **generateEcSignedPreKeyId**(): `Promise`\<`number`\>

Generate EC signed prekey ID

Returns a random ID for EC signed prekeys.
Range: 0 to 999,999

Uses CSPRNG (generateRandomBytes) instead of Math.random() for
cryptographic security.

## Returns

`Promise`\<`number`\>
