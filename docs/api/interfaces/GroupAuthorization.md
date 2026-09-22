[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupAuthorization

# Interface: GroupAuthorization

## Properties

### authorityKeyId?

> `optional` **authorityKeyId?**: `string`

Public issuer selection, not account or group authority.

***

### groupPublicParams

> **groupPublicParams**: `Uint8Array`

Serialized GroupPublicParams (identifies the group for credential verification).

***

### presentation

> **presentation**: `Uint8Array`

Serialized AuthCredentialPresentation (ZK proof of group membership).
