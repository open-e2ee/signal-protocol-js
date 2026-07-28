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

Clamped to the range [SENDER\_KEY\_AGE\_FLOOR](../variables/SENDER_KEY_AGE_FLOOR.md) to
[SENDER\_KEY\_AGE\_CEILING](../variables/SENDER_KEY_AGE_CEILING.md); a value outside it is treated as the bound
it passed, and a value that is not a positive finite number falls back to
the default.

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
