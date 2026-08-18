[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProtocolStrategyConfig

# Interface: ProtocolStrategyConfig

Protocol strategy configuration for PQXDH and SPQR.

## Properties

### allowClassicalFallback?

> `optional` **allowClassicalFallback?**: `boolean`

Allow explicit X3DH compatibility fallback for peers that advertise no
KEM/PQ material at all.

This does not allow downgrade after malformed KEM metadata, failed PQXDH
processing, or missing local KEM prekeys for incoming PQXDH messages.

#### Default

```ts
false
```

***

### keyExchangeInfoString?

> `optional` **keyExchangeInfoString?**: `string`

Override HKDF info string for both X3DH and PQXDH key derivation.

***

### networkConstraints?

> `optional` **networkConstraints?**: `NetworkConstraints`

Future automatic SCKA mode selection hints.

***

### onBraidProgress?

> `optional` **onBraidProgress?**: (`event`) => `void`

Called after each ML-KEM Braid send or receive, in braid mode only.

A direct-mode session never raises it, because direct mode carries no
chunks.

#### Parameters

##### event

`BraidProgressEvent`

#### Returns

`void`

***

### onProtocolSelected?

> `optional` **onProtocolSelected?**: (`event`) => `void`

Called after key exchange completes, before the client encrypts the first message.

#### Parameters

##### event

`ProtocolSelectionEvent`

#### Returns

`void`

***

### sckaMode?

> `optional` **sckaMode?**: [`SCKAMode`](../type-aliases/SCKAMode.md)

SCKA mode for SPQR key exchange.

#### Default

```ts
'braid'
```

***

### spqrInfoStrings?

> `optional` **spqrInfoStrings?**: `SPQRInfoStrings`

Custom SPQR HKDF info strings.

***

### spqrLimits?

> `optional` **spqrLimits?**: [`SPQRLimits`](SPQRLimits.md)

SPQR security and performance limits.
