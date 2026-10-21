[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayWakeOptions

# Interface: HostedRelayWakeOptions

## Properties

### client

> `readonly` **client**: [`HostedRelayWakeClient`](HostedRelayWakeClient.md)

***

### deadlineMs?

> `readonly` `optional` **deadlineMs?**: `number`

The time in milliseconds that the stored receives may take after the
acknowledgment. The pass stops between records at the deadline, and
the next pass continues. No limit by default.
