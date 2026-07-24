[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / ScannableFingerprint

# Class: ScannableFingerprint

Scannable fingerprint for QR code verification.

Contains binary data suitable for encoding in a QR code.
Both parties can scan each other's QR codes to verify identity.

Uses the versioned fingerprint protobuf format for cross-verification:
- When Alice scans Bob's QR, Bob's local fingerprint should equal Alice's remote
- When Bob scans Alice's QR, Alice's local fingerprint should equal Bob's remote

## Example

```typescript
const scannable = fingerprint.scannable();

// Generate QR code
const qrData = scannable.toBuffer();
const qrCode = await QRCode.toDataURL(qrData);

// Compare scanned codes (implements cross-verification)
const result = scannable.compare(scannedBuffer);
if (result === 'match') {
  // Identity verified!
}
```

## Constructors

### Constructor

> **new ScannableFingerprint**(`localFingerprint`, `remoteFingerprint`, `version?`): `ScannableFingerprint`

Create a ScannableFingerprint.

#### Parameters

##### localFingerprint

`Uint8Array`

Local user's 32-byte scannable fingerprint

##### remoteFingerprint

`Uint8Array`

Remote user's 32-byte scannable fingerprint

##### version?

`number` = `FINGERPRINT_VERSION`

Protocol version (default: 2)

#### Returns

`ScannableFingerprint`

## Methods

### compare()

> **compare**(`scannedData`): [`CompareResult`](../type-aliases/CompareResult.md)

Compare this scannable fingerprint with scanned data.

Implements cross-verification swap logic:
- Their local fingerprint should equal our remote fingerprint
- Their remote fingerprint should equal our local fingerprint

Uses best-effort full-scan equality for both fixed-size fingerprints.
JavaScript/JIT execution does not provide a hard constant-time guarantee.

#### Parameters

##### scannedData

`Uint8Array`

Raw bytes from scanned QR code

#### Returns

[`CompareResult`](../type-aliases/CompareResult.md)

'match' | 'no_match' | 'version_mismatch'

#### Example

```typescript
// After scanning their QR code
const scannedBuffer = decodeQRCode(qrImage);
const result = myFingerprint.scannable().compare(scannedBuffer);

if (result === 'match') {
  // Identity verified!
} else if (result === 'no_match') {
  // SECURITY WARNING! Keys don't match
} else if (result === 'version_mismatch') {
  // Different protocol versions
}
```

***

### compareWith()

> **compareWith**(`other`): [`CompareResult`](../type-aliases/CompareResult.md)

Compare this scannable fingerprint with another ScannableFingerprint.

Convenience method that extracts the buffer from the other fingerprint.

#### Parameters

##### other

`ScannableFingerprint`

Another ScannableFingerprint

#### Returns

[`CompareResult`](../type-aliases/CompareResult.md)

'match' | 'no_match' | 'version_mismatch'

***

### toBase64()

> **toBase64**(): `string`

Get the data as base64 string.

Useful for transmission or storage.

#### Returns

`string`

Base64-encoded fingerprint data

***

### toBuffer()

> **toBuffer**(): `Uint8Array`

Get the binary data for QR code encoding.

Encodes as protobuf CombinedFingerprints message.

#### Returns

`Uint8Array`

Uint8Array suitable for QR code generation

***

### fromBase64()

> `static` **fromBase64**(`base64`): `ScannableFingerprint`

Parse a ScannableFingerprint from base64 string.

#### Parameters

##### base64

`string`

Base64-encoded fingerprint data

#### Returns

`ScannableFingerprint`

ScannableFingerprint instance

***

### fromBuffer()

> `static` **fromBuffer**(`data`): `ScannableFingerprint`

Parse a ScannableFingerprint from raw bytes.

#### Parameters

##### data

`Uint8Array`

Protobuf-encoded fingerprint data

#### Returns

`ScannableFingerprint`

ScannableFingerprint instance
