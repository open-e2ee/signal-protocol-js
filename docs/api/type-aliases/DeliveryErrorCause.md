[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliveryErrorCause

# Type Alias: DeliveryErrorCause

> **DeliveryErrorCause** = `"content-hint"` \| `"deadline"` \| `"rate-limit"` \| `"request-ended"`

Why the client reports a delivery error for a failed envelope.

- `content-hint`: the failed envelope has the `Default` content hint, or
  no hint, so the error comes at the first failure.
- `deadline`: the failed envelope has the `Resendable` content hint, and
  its content did not come back within `RETRY_PLACEHOLDER_DEADLINE_MS`.
- `rate-limit`: a rate limit refused the retry request of the envelope.
- `request-ended`: the retry request ended with no resend, as
  `onRetryTerminal` reports.
