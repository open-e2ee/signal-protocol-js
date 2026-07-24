[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [encoding](../README.md) / base64ToUrlSafe

# Function: base64ToUrlSafe()

> **base64ToUrlSafe**(`base64`): `string`

Convert standard base64 string to URL-safe base64 string (RFC 4648 §5)

Use this when you already have a base64 string and need to make it URL-safe.
For converting bytes directly, use `bytesToUrlSafeBase64` instead.

## Parameters

### base64

`string`

Standard base64 string

## Returns

`string`

URL-safe base64 string (no +, /, or = characters)
