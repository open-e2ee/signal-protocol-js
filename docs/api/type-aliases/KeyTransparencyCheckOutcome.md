[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / KeyTransparencyCheckOutcome

# Type Alias: KeyTransparencyCheckOutcome

> **KeyTransparencyCheckOutcome** = \{ `kind`: `"pass"`; \} \| \{ `appendPending`: `boolean`; `kind`: `"not-logged"`; \} \| \{ `kind`: `"unavailable"`; `reason`: [`KeyTransparencyUnavailableReason`](KeyTransparencyUnavailableReason.md); \} \| \{ `error`: [`KeyTransparencyVerificationError`](../classes/KeyTransparencyVerificationError.md); `kind`: `"failure"`; \}

The outcome of one identity check against the log.

- `pass`: the latest log entry of the account is a key entry with the
  identity.
- `not-logged`: the log has no entry for the account. `appendPending` is
  true when the Relay says that the append waits.
- `unavailable`: the check gave no result.
- `failure`: the log or a proof contradicts the identity. `error.code`
  names the check.
