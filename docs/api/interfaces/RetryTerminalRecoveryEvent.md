[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryTerminalRecoveryEvent

# Interface: RetryTerminalRecoveryEvent

The session reset of the requester after a retry request ends as
`expired-content` or `posting-deadline`.

The requester archived its session with the device that sent the failed
envelope, after each decrypt from that device in progress ended. The next
message to or from the device starts a new session.

## Properties

### deviceId

> **deviceId**: `number`

The device ID of the device whose session the requester archived.

***

### nullMessage

> **nullMessage**: `"failed"` \| `"sent"` \| `"limited"`

`sent`: one null message went to the device and started the new session.
`limited`: a null message went to the device in the last hour, so none
was sent. `failed`: the send failed. With `limited` and `failed`, the
next ordinary message starts the new session.

***

### senderKey

> **senderKey**: `"skipped"` \| `"applied"`

`applied`: the failed message is a group message, and the requester has
a sender key for that group. The reset does not rotate the key. A key
older than `maxSenderKeyAge` rotates at the next send, as at any send,
and the new key goes to each member.
`skipped`: a pairwise message, a group message whose group the receive
did not resolve, or a group with no local sender key.

With each outcome, the reset deletes the handoff rows of each device of
that account in every group. The next send to each of those groups
gives the current key to each of those devices.

***

### userId

> **userId**: `string`

The user ID of the device whose session the requester archived.
