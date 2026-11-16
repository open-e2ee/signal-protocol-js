[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / VerificationStateSyncInput

# Interface: VerificationStateSyncInput

The verification state of one contact that a device gives to the other
devices of its account, as Signal's `Verified` sync message.

A receiving own device applies the state to its pinned identity of
`targetUserId` with `verifyContactIdentity` or `unverifyContactIdentity`.
It does not apply a sync from another account, for the own account, for a
contact with no pinned identity, or for an `identityKey` that is not the
pinned identity. A sync never pins or rotates an identity. A store without
`unverifyContactIdentity` keeps `VERIFIED` on a `default` sync. The client
logs `VERIFICATION_STATE_SYNC_NOT_APPLIED` with the reason for each sync that
it does not apply. The application still gets the sync content.

## Properties

### changedAt

> **changedAt**: `number`

***

### identityKey

> **identityKey**: `string`

The composite identity of the contact that the state is for: the base64
of `encodeCompositeIdentityV1(identity)`.

***

### state

> **state**: `"default"` \| `"verified"`

`'verified'` marks the identity verified. `'default'` clears a verification.

***

### targetUserId

> **targetUserId**: `string`

The user ID of the contact.
