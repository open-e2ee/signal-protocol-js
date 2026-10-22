[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DoubleRatchetConfig

# Interface: DoubleRatchetConfig

Double Ratchet options for one-to-one sessions.

The client reads `maxSkip` only.

## Properties

### keyExpirationMs?

> `optional` **keyExpirationMs?**: `number`

The client does not read this field. The client deletes stored skipped
message keys after 7 days (604800000 ms).

***

### maxMessageKeysStored?

> `optional` **maxMessageKeysStored?**: `number`

The client does not read this field. Each receiver chain keeps at most
2000 skipped message keys. When a chain is full, the key with the lowest
index leaves first.

***

### maxSkip?

> `optional` **maxSkip?**: `number`

Maximum number of message keys that the client skips in one receiving
chain to decrypt an out-of-order message. A message after a larger gap
fails with `TOO_MANY_SKIPPED_MESSAGES`. The value must be a positive
integer. A session with a device that has the local identity always uses
a limit of 100000.
Default: 25000
