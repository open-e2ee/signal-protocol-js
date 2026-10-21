[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryTerminalClass

# Type Alias: RetryTerminalClass

> **RetryTerminalClass** = `"missing-sender"` \| `"missing-prekey"` \| `"revoked-authority"` \| `"expired-content"` \| `"attempts-exhausted"` \| `"deletion"` \| `"abuse-allowance-exhausted"` \| `"membership-refused"`

The conclusive end of a retry request or a retry resend.

- `missing-sender`: the device that sent the failed message is gone, or
  it still refuses the request after a refresh of the session with it.
- `missing-prekey`: the Relay has no prekey bundle of the requester, so the
  sender of the resend cannot start a new session.
- `revoked-authority`: the Relay revoked the authority of the post.
- `expired-content`: the content of the request did not come before its
  deadline.
- `attempts-exhausted`: the resend that answered the fifth attempt of the
  request, `MAX_RETRY_RESPONSES_PER_MESSAGE`, also failed. The sender
  answers no later attempt.
- `deletion`: the account of the other device is deleted.
- `abuse-allowance-exhausted`: the sender used up its retry allowance.
- `membership-refused`: the requester is not a current member of the group
  of the content, or the sender has no source of current group membership.
  The sender sends no content. Only the answer of a sender ends with it.
