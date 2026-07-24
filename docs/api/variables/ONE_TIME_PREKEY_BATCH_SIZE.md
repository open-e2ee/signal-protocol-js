[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ONE\_TIME\_PREKEY\_BATCH\_SIZE

# Variable: ONE\_TIME\_PREKEY\_BATCH\_SIZE

> `const` **ONE\_TIME\_PREKEY\_BATCH\_SIZE**: `100` = `100`

Batch size for one-time prekeys (both EC and KEM)

Signal uses 100 for both EC and KEM one-time prekeys to maintain
protocol symmetry. This balances key availability with storage/upload costs.

Per PQXDH specification, KEM one-time prekeys follow the same
replenishment pattern as EC one-time prekeys.

## See

https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message
