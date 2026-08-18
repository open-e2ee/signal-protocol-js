[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SafetyNumberConfirmation

# Interface: SafetyNumberConfirmation

Exact safety-number comparison evidence.

This uses strings instead of mutable Uint8Array instances, so application code
cannot accidentally change the value between display and confirmation.

## Properties

### fingerprint

> `readonly` **fingerprint**: [`Base64`](../type-aliases/Base64.md)

Canonical Base64 of the complete displayed composite fingerprint.

***

### identityType

> `readonly` **identityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

***

### remoteIdentityCommitment

> `readonly` **remoteIdentityCommitment**: [`Base64`](../type-aliases/Base64.md)

Canonical Base64 of the locally derived remote composite commitment.

***

### userId

> `readonly` **userId**: `string`

***

### version

> `readonly` **version**: `1`
