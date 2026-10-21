[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / MAX\_MESSAGE\_KEYS

# Variable: MAX\_MESSAGE\_KEYS

> `const` **MAX\_MESSAGE\_KEYS**: `2000` = `2000`

Maximum skipped message keys to store in one receiver chain, as the reference implementation
keeps `MAX_MESSAGE_KEYS`. Past it, the key with the lowest index of that chain
leaves. `MAX_RECEIVER_CHAINS` bounds the number of chains.
