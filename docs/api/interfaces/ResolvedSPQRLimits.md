[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ResolvedSPQRLimits

# Interface: ResolvedSPQRLimits

Resolved SPQR limits with profile defaults applied.

## Properties

### maxMessageJump

> **maxMessageJump**: `number`

Max forward jump in message numbers.

#### Default

```ts
25000
```

***

### maxOutOfOrderKeys

> **maxOutOfOrderKeys**: `number`

Max out-of-order keys that each epoch keeps. A key more than this count
behind the newest received index is refused.

#### Default

```ts
2000
```
