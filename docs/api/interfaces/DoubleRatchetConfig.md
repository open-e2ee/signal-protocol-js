[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DoubleRatchetConfig

# Interface: DoubleRatchetConfig

Signal Protocol configuration options

## Properties

### keyExpirationMs?

> `optional` **keyExpirationMs?**: `number`

Key expiration time in milliseconds
Default: 7 days (604800000 ms)

***

### maxMessageKeysStored?

> `optional` **maxMessageKeysStored?**: `number`

Maximum number of skipped message keys to store
Default: 1000

***

### maxSkip?

> `optional` **maxSkip?**: `number`

Maximum number of messages to skip when receiving out-of-order messages
Default: 1000 (Signal Protocol recommendation)
