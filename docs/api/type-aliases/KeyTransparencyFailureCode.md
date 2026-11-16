[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KeyTransparencyFailureCode

# Type Alias: KeyTransparencyFailureCode

> **KeyTransparencyFailureCode** = `"VRF_PROOF_INVALID"` \| `"SEARCH_POSITION_INVALID"` \| `"INCLUSION_PROOF_INVALID"` \| `"TREE_HEAD_SIGNATURE_INVALID"` \| `"TREE_HEAD_STALE"` \| `"TREE_HEAD_INCONSISTENT"` \| `"LOGGED_KEY_MISMATCH"` \| `"LOGGED_TOMBSTONE"` \| `"IDENTITY_NOT_LOGGED"` \| `"LOG_APPEND_OVERDUE"` \| `"MALFORMED_RESPONSE"`

The code of a failed key transparency check.

- `VRF_PROOF_INVALID`: the VRF proof of the log index is not valid for the
  pinned VRF public key and the account address.
- `SEARCH_POSITION_INVALID`: the position of the entry is not inside the
  tree of the signed head.
- `INCLUSION_PROOF_INVALID`: the entry, its opening, and the inclusion path
  do not give the root of the signed head.
- `TREE_HEAD_SIGNATURE_INVALID`: no pinned head key signed the head for
  the project of the connection.
- `TREE_HEAD_STALE`: the head time is more than 24 hours from the local
  clock.
- `TREE_HEAD_INCONSISTENT`: the head does not extend the last head that the
  client verified.
- `LOGGED_KEY_MISMATCH`: the latest logged key of the account is not the
  identity that the client has for it.
- `LOGGED_TOMBSTONE`: the latest log entry of the account is a deletion.
- `IDENTITY_NOT_LOGGED`: the Relay served the identity of a contact, but
  the log has no entry for it. For the self-check, the log has no entry for
  the own account.
- `LOG_APPEND_OVERDUE`: the Relay said for 24 hours that the append of an
  identity waits.
- `MALFORMED_RESPONSE`: the Relay response does not have the form of an
  identity log result.
