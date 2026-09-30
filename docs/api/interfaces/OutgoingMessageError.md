[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / OutgoingMessageError

# Interface: OutgoingMessageError

A send failure whose exact encrypted transmission remains in the outbox.

Reuse `clientMessageId` when the application calls `send()` again after an
unknown Relay result. The durable outbox supplies the original timestamp.

A direct send attempts every device of the recipient, also when a device
before it fails, and the error is that of the first failed device. A
replay sends to every device again. The Relay keeps one copy for a device
while it remembers the result of that device. After the hosted Relay forgets
the result (60 s), the device gets a second copy and drops it as a
duplicate.

## Extends

- `Error`

## Properties

### clientMessageId

> `readonly` **clientMessageId**: `string`
