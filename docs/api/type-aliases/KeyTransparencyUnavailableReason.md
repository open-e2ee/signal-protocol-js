[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KeyTransparencyUnavailableReason

# Type Alias: KeyTransparencyUnavailableReason

> **KeyTransparencyUnavailableReason** = `"transport"` \| `"store"` \| `"race"` \| `"not-pinned"` \| `"stopped"` \| `"not-a-contact"` \| `"self-check-failing"` \| `"rate-limited"`

Why a key transparency check gave no result. The reason holds no address
and no key.

- `transport`: a network error or a Relay error status, also a 429.
- `store`: a local store read or write failed.
- `race`: other clients on the store changed the verified head three times.
- `not-pinned`: the client has no pinned identity log keys, so it runs no
  check.
- `stopped`: the client is not started, or it stopped.
- `not-a-contact`: the user is the own account, or the store has no pinned
  identity for the user.
- `self-check-failing`: the self-check of the own identity is failing.
- `rate-limited`: the cap of requested checks is full. Try again later.

The background checks give only `transport`, `store`, and `race`.
