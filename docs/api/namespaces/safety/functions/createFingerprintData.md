[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / createFingerprintData

# Function: createFingerprintData()

> **createFingerprintData**(`localIdentityKey`, `remoteIdentityKey`, `localIdentifier`, `remoteIdentifier`): [`FingerprintData`](../interfaces/FingerprintData.md)

Create fingerprint data from identity keys and identifiers.

This is a convenience function that wraps the Fingerprint class
and provides compatibility with the existing function-based API.

## Parameters

### localIdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

Our identity public key

### remoteIdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

Their identity public key

### localIdentifier

`string`

Our user ID

### remoteIdentifier

`string`

Their user ID

## Returns

[`FingerprintData`](../interfaces/FingerprintData.md)

FingerprintData with all representations

## Example

```typescript
const data = createFingerprintData(
  myKey,
  theirKey,
  'alice@example.com',
  'bob@example.com'
);

console.log(data.formatted); // Formatted for display
const qrCode = generateQRCode(data.scannable); // For scanning
```
