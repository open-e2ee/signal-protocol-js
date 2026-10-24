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
message keys that are older than 7 days (604800000 ms). The deletion is
lazy. It runs before the client encrypts or decrypts a message in the
session, and in `DefaultSignalProtocolClient.cleanupExpiredKeys()`. No
timer runs it, so an old key stays stored until the next such call.

***

### maxMessageKeysStored?

> `optional` **maxMessageKeysStored?**: `number`

The client does not read this field. Each receiver chain keeps at most
2000 skipped message keys. When a chain is full, the key with the lowest
index leaves first. A key older than 7 days also leaves, at the next
expiry cleanup. See `keyExpirationMs`.

***

### maxSkip?

> `optional` **maxSkip?**: `number`

Maximum number of message keys that the client skips in one receiving
chain to decrypt an out-of-order message. A message after a larger gap
fails with `TOO_MANY_SKIPPED_MESSAGES`. The value must be a positive
integer. A session with a device that has the local identity always uses
a limit of 100000.
Default: 25000
