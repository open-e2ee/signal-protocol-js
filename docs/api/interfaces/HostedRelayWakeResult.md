[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayWakeResult

# Interface: HostedRelayWakeResult

## Properties

### acknowledgedMessageIds

> `readonly` **acknowledgedMessageIds**: readonly `string`[]

***

### failedMessageIds

> `readonly` **failedMessageIds**: readonly `string`[]

***

### pulled

> `readonly` **pulled**: `number`

***

### retainedWork?

> `readonly` `optional` **retainedWork?**: `boolean`

True when the Relay keeps work after the page of this pass: a message
after the page, or a Relay receipt that the page does not carry. Run
another pass to get it. False when the page carried all retained work.
Absent when the Relay does not report it. Then the retained work is
unknown, so do not read an absent value as false.
