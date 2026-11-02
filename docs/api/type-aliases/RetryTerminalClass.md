[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryTerminalClass

# Type Alias: RetryTerminalClass

> **RetryTerminalClass** = `"missing-sender"` \| `"missing-prekey"` \| `"revoked-authority"` \| `"request-expired"` \| `"posting-deadline"` \| `"attempts-exhausted"` \| `"deletion"` \| `"abuse-allowance-exhausted"` \| `"membership-refused"`

The conclusive end of a retry request or a retry resend.

- `missing-sender`: the device that sent the failed message is gone, or
  it still refuses the request after a refresh of the session with it.
- `missing-prekey`: the Relay has no prekey bundle of the requester, so the
  sender of the resend cannot start a new session.
- `revoked-authority`: the Relay revoked the authority of the post.
- `request-expired`: the Relay answered or holds the latest attempt of the
  request, and the content did not come before its deadline. The session
  does not reset. This class is not the delivery error cause
  `request-ended`.
- `posting-deadline`: a post of the request was due at or after its
  posting deadline, the Relay refused a post with OPERATION_EXPIRED, or
  the request got to its deadline and the Relay did not accept its latest
  attempt; the session resets.
- `attempts-exhausted`: the resend that answered the fifth attempt of the
  request, `MAX_RETRY_RESPONSES_PER_MESSAGE`, also failed. The sender
  answers no later attempt.
- `deletion`: the account of the other device is deleted.
- `abuse-allowance-exhausted`: the sender used up its retry allowance.
- `membership-refused`: the requester is not a current member of the group
  of the content, or the sender has no source of current group membership.
  The sender sends no content. Only the answer of a sender ends with it.
