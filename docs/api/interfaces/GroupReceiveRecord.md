[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupReceiveRecord

# Interface: GroupReceiveRecord

The receive record of one group.

## Properties

### init

> **init**: [`GroupFetchState`](GroupFetchState.md)

***

### requiredRevision

> **requiredRevision**: `number`

The highest revision that an authenticated group context from any
sender claimed since the last fetch that reached the server head. That
fetch sets it to the head, so a claim above the head holds the group
stale only until the fetch for it. Local state below it is stale.

***

### source

> **source**: [`GroupRecordSource`](../type-aliases/GroupRecordSource.md)

***

### unverified?

> `optional` **unverified?**: [`GroupUnverifiedOrigin`](GroupUnverifiedOrigin.md)

Set while a group that a sender's context created has never verified.
