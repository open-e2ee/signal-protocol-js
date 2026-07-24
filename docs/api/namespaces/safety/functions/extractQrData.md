[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / extractQrData

# Function: extractQrData()

> **extractQrData**(`scannedData`, `config?`): `string` \| `null`

Extract QR data from a scanned string.

Handles both URL format and legacy raw base64 format.
This is a convenience function for the QR scanner.

## Parameters

### scannedData

`string`

Raw data from QR scanner

### config?

[`VerifyLinkConfig`](../interfaces/VerifyLinkConfig.md) = `DEFAULT_VERIFY_LINK_CONFIG`

Link configuration (defaults to [DEFAULT\_VERIFY\_LINK\_CONFIG](../variables/DEFAULT_VERIFY_LINK_CONFIG.md))

## Returns

`string` \| `null`

Base64 protobuf data, or null if invalid
