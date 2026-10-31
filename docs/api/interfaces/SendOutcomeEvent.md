[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SendOutcomeEvent

# Interface: SendOutcomeEvent

The end of one send or of one manual resend of it, or an open send whose
content the SDK send driver cannot find.

## Properties

### clientMessageId

> `readonly` **clientMessageId**: `string`

The client message ID of the send.

***

### deadlineAt

> `readonly` **deadlineAt**: `number`

The posting deadline of the send, in epoch milliseconds.

***

### error?

> `readonly` `optional` **error?**: `Error`

The error of a `failed` or `acceptance-unknown` end, as a `send()` call
with the same `clientMessageId` throws it.

***

### manualResend?

> `readonly` `optional` **manualResend?**: `number`

The number of the manual resend that ended, from 1, for the end of a
`resendMessage` operation. The event then carries the `deadlineAt`, and
the `result` or `error`, of that resend. It is absent for the end of
the original send.

***

### outcome

> `readonly` **outcome**: `"failed"` \| `"completed"` \| `"acceptance-unknown"` \| `"content-required"`

`completed`: the Relay accepted the send, and `result` holds its result.
`failed` and `acceptance-unknown`: the send ended at its posting
deadline, and `error` holds the error of the end.
`content-required`: the send is open, and the driver did not find its
plaintext, or the plaintext that it found does not match the send. The
send stays open until its posting deadline. Call `send()` again with the
same `clientMessageId` and content before `deadlineAt`.

***

### result?

> `readonly` `optional` **result?**: [`SendResult`](SendResult.md)

The result of a `completed` send.
