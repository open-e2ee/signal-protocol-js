[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / OutgoingMessageError

# Interface: OutgoingMessageError

A send failure that carries the logical-send identifier.

`isOutgoingMessageError` is true for every send error, also for an error
before the SDK stores the send, such as a failed content serialization or
a failed read of the own device list on a relay that does not compare
device sets. The exact encrypted transmission stays in the outbox only for a send
that the SDK already stored. In both cases, the application calls `send()`
again with the same `clientMessageId`. For a stored send, the durable
outbox supplies the original timestamp. For a send that the SDK did not
store, the SDK encrypts the content again.

A direct send attempts every device of the recipient, also when a device
before it fails, and the error is that of the first failed device. A
replay sends to every device again. The Relay keeps one copy for a device
while it remembers the result of that device. After the Relay forgets the
result (60 s), the device gets a second copy and drops it as a duplicate.

## Extends

- `Error`

## Properties

### clientMessageId

> `readonly` **clientMessageId**: `string`
