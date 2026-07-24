[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [safety](../README.md) / VerifyLinkConfig

# Interface: VerifyLinkConfig

Configuration for safety-number verification deep links.

Both fields are required so a config is always fully specified; use
[DEFAULT\_VERIFY\_LINK\_CONFIG](../variables/DEFAULT_VERIFY_LINK_CONFIG.md) as a base when overriding a single field.

## Properties

### baseUrl

> **baseUrl**: `string`

Universal-link base, including path (e.g. `https://verify.example.com/safety-number`).

***

### schemeUrl

> **schemeUrl**: `string`

Custom URL scheme prefix (e.g. `example://verify`).
