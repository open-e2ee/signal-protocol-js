[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliveryRecoveredEvent

# Interface: DeliveryRecoveredEvent

The recovery of one failed incoming envelope that had a delivery error.

## Extended by

- [`DeliveryErrorEvent`](DeliveryErrorEvent.md)

## Properties

### clientMessageId?

> `optional` **clientMessageId?**: `string`

The client message ID of the failed envelope, when its relay delivered one.

***

### failedEnvelopeId

> **failedEnvelopeId**: `string`

The Relay message ID of the envelope that the local device failed to decrypt.

***

### groupId?

> `optional` **groupId?**: `string`

The group of a failed group message, in the form of
`DecryptedEnvelope.conversationId`. A group envelope names no group, so
the client knows it only when it holds the sender key that the message
names. The error of a message that failed for a missing sender key has
none. Its recovery has one when the decrypt that gave the content
installed or used the sender key of the group. `processIncomingEnvelope`
gives a resend's distribution to the caller and installs no key, so
its recovery can have none.

***

### groupMessage

> **groupMessage**: `boolean`

True when the failed envelope is a sender-key group message.

***

### receivedAt

> **receivedAt**: `number`

The time of the first failure of the envelope, in epoch milliseconds.

***

### senderDeviceId

> **senderDeviceId**: `number`

The device that sent the failed envelope.

***

### senderUserId

> **senderUserId**: `string`

The user that sent the failed envelope.
