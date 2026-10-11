[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryTerminalClass

# Type Alias: RetryTerminalClass

> **RetryTerminalClass** = `"missing-sender"` \| `"missing-prekey"` \| `"revoked-authority"` \| `"expired-content"` \| `"deletion"` \| `"abuse-allowance-exhausted"`

The conclusive end of a retry request or a retry resend.

- `missing-sender`: the device that sent the failed message is gone.
- `missing-prekey`: the Relay has no prekey bundle of the requester, so the
  sender of the resend cannot start a new session.
- `revoked-authority`: the Relay revoked the authority of the post.
- `expired-content`: the request got no answer before its deadline.
- `deletion`: the account of the other device is deleted.
- `abuse-allowance-exhausted`: the sender used up its retry allowance.
