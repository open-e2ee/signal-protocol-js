[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / parseVerifyUrl

# Function: parseVerifyUrl()

> **parseVerifyUrl**(`url`, `config?`): [`VerifyUrlParams`](../interfaces/VerifyUrlParams.md) \| `null`

Parse a verification URL and extract parameters.

## Parameters

### url

`string`

Verification URL to parse

### config?

[`VerifyLinkConfig`](../interfaces/VerifyLinkConfig.md) = `DEFAULT_VERIFY_LINK_CONFIG`

Link configuration (defaults to [DEFAULT\_VERIFY\_LINK\_CONFIG](../variables/DEFAULT_VERIFY_LINK_CONFIG.md))

## Returns

[`VerifyUrlParams`](../interfaces/VerifyUrlParams.md) \| `null`

Parsed parameters, or null if URL is invalid
