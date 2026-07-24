[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [encoding](../README.md) / bytesToUrlSafeBase64

# Function: bytesToUrlSafeBase64()

> **bytesToUrlSafeBase64**(`bytes`): `string`

Convert Uint8Array to URL-safe Base64 string (RFC 4648 §5)

URL-safe Base64 uses:
- `-` instead of `+`
- `_` instead of `/`
- No padding (`=`)

Used for R2 storage keys (attachments, profiles) following the Signal
Messenger storage-key pattern.

## Parameters

### bytes

`Uint8Array`

## Returns

`string`

## See

RFC 4648 Section 5 - Base 64 Encoding with URL and Filename Safe Alphabet
