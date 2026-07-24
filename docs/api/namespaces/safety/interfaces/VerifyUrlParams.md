[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / VerifyUrlParams

# Interface: VerifyUrlParams

Parameters encoded in a verification URL.

## Properties

### contextId

> **contextId**: `string`

Context ID (conversation or dynamic ID)

***

### contextType

> **contextType**: `"dm"` \| `"dynamic"`

Context type: direct message or dynamic group

***

### generatorUserId

> **generatorUserId**: `string`

The user who generated the QR code (self from generator's perspective)

***

### otherUserId

> **otherUserId**: `string`

Other user's Convex ID (from generator's perspective)

***

### qrData

> **qrData**: `string`

Base64-encoded protobuf fingerprint data
