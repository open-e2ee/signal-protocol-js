[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayPresenceStatus

# Interface: HostedRelayPresenceStatus

One account's presence, as its reader may see it.

## Properties

### lastSeen

> `readonly` **lastSeen**: `number` \| [`HostedRelayPresenceApproximateLastSeen`](../type-aliases/HostedRelayPresenceApproximateLastSeen.md) \| `null`

Milliseconds since the epoch under the `exact` policy, a range under
`approximate`, and null under `hidden` or when no device was seen.

***

### online

> `readonly` **online**: `boolean`
