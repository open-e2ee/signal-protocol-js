[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / OutgoingMessageError

# Interface: OutgoingMessageError

A send failure whose exact encrypted transmission remains in the outbox.

Reuse `clientMessageId` when the application calls `send()` again after an
unknown Relay result. The durable outbox supplies the original timestamp.

## Extends

- `Error`

## Properties

### clientMessageId

> `readonly` **clientMessageId**: `string`
