[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / generateEmojiFingerprint

# Function: generateEmojiFingerprint()

> **generateEmojiFingerprint**(`hash`): `string`

Generate emoji fingerprint (30 emojis).

Uses consecutive bytes from the 64-byte SHA-512 hash.
No re-hashing needed - the hash has more than enough entropy.

## Parameters

### hash

`Uint8Array`

## Returns

`string`
