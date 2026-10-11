[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RetryTerminalEvent

# Interface: RetryTerminalEvent

The end of a retry request with no resend. The device that asked for the
resend gets it for each class except `missing-prekey`. The device that
sent the failed message gets `missing-prekey`, when it cannot start a new
session with the requester. Each request ends once, and the hook runs once
for it.

## Properties

### class

> **class**: [`RetryTerminalClass`](../type-aliases/RetryTerminalClass.md)

Why the request ended.

***

### failedEnvelopeId

> **failedEnvelopeId**: `string`

The Relay message ID of the envelope that the requester failed to decrypt.
