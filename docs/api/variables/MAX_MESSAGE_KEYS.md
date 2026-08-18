[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MAX\_MESSAGE\_KEYS

# Variable: MAX\_MESSAGE\_KEYS

> `const` **MAX\_MESSAGE\_KEYS**: `2000` = `2000`

Maximum total message keys to store across all receiver chains.

This is a global limit, not per-chain. Past it, a FIFO strategy evicts the
oldest keys.
