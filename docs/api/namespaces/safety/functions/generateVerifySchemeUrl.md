[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / generateVerifySchemeUrl

# Function: generateVerifySchemeUrl()

> **generateVerifySchemeUrl**(`params`, `config?`): `string`

Generate a verification URL using the custom scheme.
Useful for local development or when universal links aren't configured.

## Parameters

### params

[`VerifyUrlParams`](../interfaces/VerifyUrlParams.md)

Verification parameters to encode

### config?

[`VerifyLinkConfig`](../interfaces/VerifyLinkConfig.md) = `DEFAULT_VERIFY_LINK_CONFIG`

Link configuration (defaults to [DEFAULT\_VERIFY\_LINK\_CONFIG](../variables/DEFAULT_VERIFY_LINK_CONFIG.md))

## Returns

`string`

Custom scheme URL string
