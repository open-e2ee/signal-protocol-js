[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / SafetyNumber

# Interface: SafetyNumber

Safety number result with multiple representations

## Properties

### emojis

> **emojis**: `string`

Emoji representation (30 emojis)

***

### hex

> **hex**: `string`

Raw hex fingerprint

***

### numeric

> **numeric**: `string`

60-digit number formatted in groups of 5

***

### qrData

> **qrData**: `string`

QR code data as base64 (protobuf format)

***

### scannable

> **scannable**: [`ScannableFingerprint`](../classes/ScannableFingerprint.md)

ScannableFingerprint instance for verification
