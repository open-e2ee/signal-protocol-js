[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolConfig

# Interface: SignalProtocolConfig

Public Signal Protocol configuration.

This keeps application code in product/security terms. Internal protocol
strategy details such as X3DH fallback remain below the SignalProtocolClient seam.

## Properties

### braid?

> `optional` **braid?**: [`BraidPolicy`](../type-aliases/BraidPolicy.md)

ML-KEM Braid policy for the ongoing post-quantum ratchet.

- `required`: use the specification-defined ML-KEM Braid SPQR profile.
- `disabled`: explicitly use the direct ML-KEM SPQR mode instead.

Direct mode remains post-quantum, but it is a separate SDK SPQR mode.
Prefer `required` unless a product-reviewed constraint needs direct mode.

#### Default

```ts
'required'
```

***

### postQuantum?

> `optional` **postQuantum?**: [`PostQuantumPolicy`](../type-aliases/PostQuantumPolicy.md)

Post-quantum policy for session establishment.

- `required`: require post-quantum peers; peers without PQ material fail closed.
- `compatible`: use post-quantum peers when available and allow classical
  compatibility only for peers with no PQ material at all.

#### Default

```ts
'required'
```
