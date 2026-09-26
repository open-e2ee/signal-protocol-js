[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayPresenceErrorCode

# Type Alias: HostedRelayPresenceErrorCode

> **HostedRelayPresenceErrorCode** = `"PRESENCE_SETTING_FORCED"` \| `"INVALID_TRANSITION"` \| `"QUOTA_EXCEEDED"` \| `"NOT_CONNECTED"` \| `"TIMEOUT"` \| `"BUSY"` \| `"FRAME_REJECTED"` \| `string` & `object`

A presence error code. The Relay sends its own codes, for example
`PRESENCE_SETTING_FORCED` for a setting write under the `forced` mode,
`INVALID_TRANSITION` for a write under the `off` mode, and
`QUOTA_EXCEEDED` for too many reads. The SDK adds four codes:
`NOT_CONNECTED` when no mailbox socket is live or the socket left before
the answer, `TIMEOUT` when no answer arrives in 10 s, `BUSY` when too many
requests wait for an answer, and `FRAME_REJECTED` when the Relay closed the
socket with 1008 because it does not accept presence frames.
