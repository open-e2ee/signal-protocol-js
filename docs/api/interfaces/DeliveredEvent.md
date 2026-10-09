[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeliveredEvent

# Interface: DeliveredEvent

The delivery of one outgoing message to one recipient device.

## Properties

### clientMessageId

> **clientMessageId**: `string`

The client message ID of the send.

***

### clientTimestamp

> **clientTimestamp**: `number`

The client timestamp of the send.

***

### decryptionConfirmed

> **decryptionConfirmed**: `boolean`

True when `sources` includes `'e2ee'`: the device decrypted the message.

***

### deliveredAt

> **deliveredAt**: `number`

The time of the first source, in epoch milliseconds.

***

### groupId?

> `optional` **groupId?**: `string`

The group ID, for a group message.

***

### recipientDeviceId

> **recipientDeviceId**: `number`

The recipient device.

***

### recipientId

> **recipientId**: `string`

The recipient user. For a group message, the group member.

***

### source

> **source**: [`DeliverySource`](../type-aliases/DeliverySource.md)

The source that this event reports.

***

### sources

> **sources**: [`DeliverySource`](../type-aliases/DeliverySource.md)[]

Each source of the delivery so far, in the order of arrival.
