[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / isVerifyUrl

# Function: isVerifyUrl()

> **isVerifyUrl**(`data`, `config?`): `boolean`

Re-export URL utilities for safety number deep links.

These enable QR codes to work with native camera apps (iOS/Android).
When scanned outside the app, the URL opens to the verification screen.

## Parameters

### data

`string`

### config?

[`VerifyLinkConfig`](../interfaces/VerifyLinkConfig.md) = `DEFAULT_VERIFY_LINK_CONFIG`

## Returns

`boolean`

## Example

```typescript
import { generateVerifyUrl, extractQrData } from './';

// Generate URL for QR code display
const url = generateVerifyUrl({
  otherUserId: 'abc123',
  contextType: 'dm',
  contextId: 'xyz789',
  qrData: safetyNumber.qrData,
});

// Extract QR data from scanned URL or legacy format
const data = extractQrData(scannedString);
```
