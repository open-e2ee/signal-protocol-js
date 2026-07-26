[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MAX\_RECEIVER\_CHAINS

# Variable: MAX\_RECEIVER\_CHAINS

> `const` **MAX\_RECEIVER\_CHAINS**: `5` = `5`

Maximum number of receiver chains to store.

The reference implementation maintains up to 5 receiver chains for handling out-of-order
DH ratchets. When a 6th chain would be added, the oldest is evicted.
