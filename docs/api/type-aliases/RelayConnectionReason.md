[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayConnectionReason

# Type Alias: RelayConnectionReason

> **RelayConnectionReason** = `"handshake"` \| `"protocol"` \| `"closed"` \| `"error"` \| `"frame"` \| `"authentication"` \| `"silent"`

The transition site that moved a relay connection to `reconnecting`.

- `handshake`: the socket did not open within 10 seconds.
- `protocol`: the socket opened with a subprotocol other than the mailbox one.
- `closed`: the socket closed.
- `error`: the socket reported an error, or a frame could not be sent.
- `frame`: the socket delivered a frame that the client refuses.
- `authentication`: the device token for the socket could not be issued.
- `silent`: the Relay did not answer a ping before the next one was due.
