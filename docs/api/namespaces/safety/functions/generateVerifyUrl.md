[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / generateVerifyUrl

# Function: generateVerifyUrl()

> **generateVerifyUrl**(`params`, `config?`): `string`

Generate a verification deep link URL for QR code display.

The URL contains all information needed to:
1. Open the app (via universal link or custom scheme)
2. Navigate to the correct safety number verification screen
3. Display the fingerprint for manual comparison

## Parameters

### params

[`VerifyUrlParams`](../interfaces/VerifyUrlParams.md)

Verification parameters to encode

### config?

[`VerifyLinkConfig`](../interfaces/VerifyLinkConfig.md) = `DEFAULT_VERIFY_LINK_CONFIG`

Link configuration (defaults to [DEFAULT\_VERIFY\_LINK\_CONFIG](../variables/DEFAULT_VERIFY_LINK_CONFIG.md))

## Returns

`string`

Full URL string for QR code

## Example

```typescript
const url = generateVerifyUrl({
  generatorUserId: 'my_user_id_xyz789',
  otherUserId: 'jx79f527wxe7k89cn9xq4zh4n97yhyp1',
  contextType: 'dm',
  contextId: 'kh72g638yxf8l90do0yr5zi5o08ziyr2',
  qrData: 'CAISIgoguD3Fkj...',
});
// Returns: https://verify.open-e2ee.dev/safety-number?g=my_user_id_xyz789&u=jx79f527...&t=dm&c=...&d=...
```
