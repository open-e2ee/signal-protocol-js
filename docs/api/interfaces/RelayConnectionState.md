[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayConnectionState

# Interface: RelayConnectionState

The local device's relay connection, as its envelope subscription sees it.

- `stopped`: no subscription is running.
- `connecting`: the subscription started and has not connected yet.
- `connected`: the subscription has a live connection.
- `reconnecting`: the connection failed and the subscription retries it.

`reason` names the transition site of the last move to `reconnecting`. It is
never an error message. `since` is the Unix time in milliseconds of the
transition. A planned token renewal on a live connection is not a transition.

## Properties

### reason?

> `readonly` `optional` **reason?**: [`RelayConnectionReason`](../type-aliases/RelayConnectionReason.md)

***

### since

> `readonly` **since**: `number`

***

### state

> `readonly` **state**: `"connected"` \| `"stopped"` \| `"connecting"` \| `"reconnecting"`
