[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / encodeGroupTrustRoot

# Function: encodeGroupTrustRoot()

> **encodeGroupTrustRoot**(`trustRoot`): `Uint8Array`

Encode a group trust root into its versioned binary representation.

Version 1 is fixed-width:
`version || signing-key length || credential key || signing key ||
profile-key credential key || endorsement root`.

The signing-key length is either 32 for a conforming S9/S14 deployment or
zero for §12.3's explicitly selected non-conforming mode.

## Parameters

### trustRoot

[`GroupTrustRoot`](../interfaces/GroupTrustRoot.md)

## Returns

`Uint8Array`
