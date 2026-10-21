[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliveryErrorEvent

# Interface: DeliveryErrorEvent

The delivery error of one failed incoming envelope.

## Extends

- [`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md)

## Properties

### cause

> **cause**: [`DeliveryErrorCause`](../type-aliases/DeliveryErrorCause.md)

Why the client reports the error now.

***

### clientMessageId?

> `optional` **clientMessageId?**: `string`

The client message ID of the failed envelope, when its relay delivered one.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`clientMessageId`](DeliveryRecoveredEvent.md#clientmessageid)

***

### failedEnvelopeId

> **failedEnvelopeId**: `string`

The Relay message ID of the envelope that the local device failed to decrypt.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`failedEnvelopeId`](DeliveryRecoveredEvent.md#failedenvelopeid)

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

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`groupId`](DeliveryRecoveredEvent.md#groupid)

***

### groupMessage

> **groupMessage**: `boolean`

True when the failed envelope is a sender-key group message.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`groupMessage`](DeliveryRecoveredEvent.md#groupmessage)

***

### receivedAt

> **receivedAt**: `number`

The time of the first failure of the envelope, in epoch milliseconds.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`receivedAt`](DeliveryRecoveredEvent.md#receivedat)

***

### senderDeviceId

> **senderDeviceId**: `number`

The device that sent the failed envelope.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`senderDeviceId`](DeliveryRecoveredEvent.md#senderdeviceid)

***

### senderUserId

> **senderUserId**: `string`

The user that sent the failed envelope.

#### Inherited from

[`DeliveryRecoveredEvent`](DeliveryRecoveredEvent.md).[`senderUserId`](DeliveryRecoveredEvent.md#senderuserid)
