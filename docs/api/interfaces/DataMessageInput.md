[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DataMessageInput

# Interface: DataMessageInput

Minimal structured message input for SignalProtocolClient.send().
Matches the shape of DataMessage from the content layer without importing it.
Any object with a `timestamp` field (and no Blob/Uint8Array prototype) qualifies.

## Indexable

> \[`key`: `string`\]: `unknown`

## Properties

### timestamp?

> `optional` **timestamp?**: `number`

The send timestamp, in milliseconds since the epoch. Default: the SDK
clock. A new send accepts a safe positive integer at most 5 minutes ahead
of the SDK clock and at most 24 hours behind it, and throws
`InvalidSendTimestampError` for any other value.
