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
replay sends to every device again, with the stored bytes and the stored
timestamp. The Relay keeps one copy for a device while it remembers the
result of that device. From the Relay release that follows v2026.10.25, it
remembers the result for 24 hours after the timestamp of the send.

A direct or group send has a posting deadline, `deadlineAt`: the earlier of 24 hours
after the SDK first stores the send and 24 hours after its timestamp. A
replay or a restart never moves it. At or after it, the SDK starts no
request for the send, and the replay ends with the stored result or error.
The outbox keeps a send for 30 days after it stores it. A replay after that
time is a new send, with a new timestamp and a new deadline.

## Extends

- `Error`

## Properties

### acceptedDevices?

> `readonly` `optional` **acceptedDevices?**: readonly `object`[]

The devices that the Relay accepted, when the send ended at its deadline.

***

### clientMessageId

> `readonly` **clientMessageId**: `string`

***

### deadlineAt?

> `readonly` `optional` **deadlineAt?**: `number`

The posting deadline of a stored send, in milliseconds since the epoch.
Absent when the SDK did not store the send.

***

### refusedDevices?

> `readonly` `optional` **refusedDevices?**: readonly `object`[]

The devices that the Relay refused, when the send ended at its deadline.

***

### relayRetryable?

> `readonly` `optional` **relayRetryable?**: `boolean`

The Relay's own `retryable` hint, when the SDK set `retryable`.

***

### retryable?

> `readonly` `optional` **retryable?**: `boolean`

True on a send error before `deadlineAt` that leaves a device open: a
replay with the same `clientMessageId` can post it. False when the send
ended at its deadline. Absent on an error that keeps its own retry rule.
