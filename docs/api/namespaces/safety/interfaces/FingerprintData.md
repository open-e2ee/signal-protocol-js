[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / FingerprintData

# Interface: FingerprintData

Fingerprint data for compatibility with existing function-based API.

This interface matches the existing `SafetyNumber` interface but is
extended to support the new class-based API.

## Properties

### fingerprint

> **fingerprint**: [`Fingerprint`](../classes/Fingerprint.md)

Fingerprint instance for advanced operations

***

### formatted

> **formatted**: `string`

Formatted numeric fingerprint (with spaces)

***

### numeric

> **numeric**: `string`

60-digit numeric fingerprint

***

### scannable

> **scannable**: `string`

Base64-encoded scannable data for QR codes (protobuf format)

***

### scannableFingerprint

> **scannableFingerprint**: [`ScannableFingerprint`](../classes/ScannableFingerprint.md)

ScannableFingerprint instance for verification
