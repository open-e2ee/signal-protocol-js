[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / Fingerprint

# Class: Fingerprint

Fingerprint for identity verification between two parties.

Contains both displayable (numeric) and scannable (QR code) representations
of the combined identity fingerprint. Provides Fingerprint class.

Deterministic party ordering ensures both participants compute the same
fingerprint value.

## Example

```typescript
const fingerprint = new Fingerprint(
  myIdentityKey,
  theirIdentityKey,
  myUserId,
  theirUserId
);

// Show displayable fingerprint in UI
const displayable = fingerprint.displayable();
console.log(displayable.toString()); // "60-digit number"

// Generate QR code for scanning
const scannable = fingerprint.scannable();
const qrData = scannable.toBuffer();
```

## Constructors

### Constructor

> **new Fingerprint**(`localIdentityKey`, `remoteIdentityKey`, `localIdentifier`, `remoteIdentifier`): `Fingerprint`

Create a new Fingerprint.

#### Parameters

##### localIdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

Our identity public key

##### remoteIdentityKey

[`PublicKey`](../../../type-aliases/PublicKey.md)

Their identity public key

##### localIdentifier

`string`

Our user ID

##### remoteIdentifier

`string`

Their user ID

#### Returns

`Fingerprint`

## Methods

### displayable()

> **displayable**(): [`DisplayableFingerprint`](DisplayableFingerprint.md)

Get displayable fingerprint for manual verification.

Returns a 60-digit numeric string formatted for easy comparison.

#### Returns

[`DisplayableFingerprint`](DisplayableFingerprint.md)

DisplayableFingerprint instance

***

### scannable()

> **scannable**(): [`ScannableFingerprint`](ScannableFingerprint.md)

Get scannable fingerprint for QR code verification.

Returns binary data suitable for QR code encoding.

#### Returns

[`ScannableFingerprint`](ScannableFingerprint.md)

ScannableFingerprint instance
