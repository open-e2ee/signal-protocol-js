[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SenderKeysConfig

# Interface: SenderKeysConfig

Sender Keys (group messaging) configuration options.

## Properties

### hkdfInfoString?

> `optional` **hkdfInfoString?**: `string`

HKDF info string for message key derivation.

#### Default

```ts
"WhisperGroup"
```

***

### maxChainAdvance?

> `optional` **maxChainAdvance?**: `number`

Maximum chain advancement per message.

#### Default

```ts
25000
```

***

### maxSenderKeyAge?

> `optional` **maxSenderKeyAge?**: `number`

Maximum age for locally generated sender keys before rotation.

#### Default

```ts
1209600000
```

***

### maxSkippedKeys?

> `optional` **maxSkippedKeys?**: `number`

Maximum skipped message keys to store per sender.

#### Default

```ts
2000
```
