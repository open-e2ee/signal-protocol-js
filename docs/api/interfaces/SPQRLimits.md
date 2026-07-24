[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SPQRLimits

# Interface: SPQRLimits

SPQR security and performance limits.

Defaults bound a forward jump to 25,000 and retained out-of-order keys to
2,000.

## Properties

### maxMessageJump?

> `optional` **maxMessageJump?**: `number`

Maximum forward jump in message numbers.

#### Default

```ts
25000
```

***

### maxOutOfOrderKeys?

> `optional` **maxOutOfOrderKeys?**: `number`

Maximum out-of-order keys to store.

#### Default

```ts
2000
```
