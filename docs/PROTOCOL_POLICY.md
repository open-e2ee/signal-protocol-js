# Protocol Policy Guide

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) | [Security](./SECURITY.md) | [Getting Started](./GETTING_STARTED.md) | **Protocol Policy** | [Deviations](./DEVIATIONS.md)

This document covers **which protocol modes run** and which fail closed.
[Deviations](./DEVIATIONS.md) covers **how the profile differs from the
published specifications and from `libsignal`**. That includes the composite
identity, the Ed25519-instead-of-XEdDSA signature scheme, the ML-KEM Braid
`hek` operand order, and every other difference.

The public Signal Protocol client policy is:

```ts
protocol: {
  postQuantum: 'required',
  braid: 'required',
}
```

Both values are the defaults.

`createSignalProtocolClient()` is the canonical application entry point from
`@open-e2ee/signal-protocol-sdk`. `storage` and `relay` are the adapters for
the current app.

## Required

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'required' },
});
```

Required mode means post-quantum session establishment and the post-quantum
message ratchet are mandatory. A peer that has no post-quantum material fails
closed.

## Compatible

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'compatible', braid: 'required' },
});
```

Compatible mode still uses post-quantum behavior whenever the peer supports it.
It only allows classical compatibility when the peer advertises no
post-quantum material at all.

Compatible mode does not allow downgrade recovery:

- malformed post-quantum metadata fails closed
- cryptographic failure after post-quantum selection fails closed
- missing referenced local post-quantum prekey material fails closed
- successful post-quantum establishment keeps the post-quantum message ratchet
  mandatory

## Braid Policy

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'required' },
});
```

`braid: 'required'` uses the specification-defined ML-KEM Braid SPQR profile
and is the default. HEK is `SHA3-256(ek_seed || ek_vector)`. That operand order
is part of the public compatibility boundary. It follows the ML-KEM Braid
specification text and reverses `libsignal`'s implementation. Braid sessions
therefore do not interoperate with `libsignal`'s, and the KEM in this mode is
not stock FIPS 203.

See [Deviations §4.1](./DEVIATIONS.md#41-the-hek-operand-order-diverges).

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'disabled' },
});
```

`braid: 'disabled'` keeps post-quantum session establishment required but uses
the local direct ML-KEM SPQR mode. This is an explicit escape hatch for
product-reviewed constraints, not downgrade recovery.

## Constants

Use string literals directly or the exported constant object:

```ts
import { BraidPolicy, PostQuantumPolicy, createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: PostQuantumPolicy.Required,
    braid: BraidPolicy.Required,
  },
});
```

There is no public `postQuantum: 'disabled'` mode.

## Advanced Telemetry

The advanced `protocolStrategy.onProtocolSelected` callback remains available
for diagnostics. It distinguishes post-quantum success from explicit classical
compatibility fallback. Do not set `protocolStrategy.allowClassicalFallback`
when `protocol.postQuantum` is present.

The advanced `protocolStrategy.onBraidProgress` callback reports ML-KEM Braid
chunk progress after every braid-mode send and receive:

- the chunks this side carried in the current epoch
- the chunks the open transfers account for
- the epoch
- whether the operation produced the epoch secret

A direct-mode session never raises it.

Do not set `protocolStrategy.sckaMode` when `protocol` is present. Use
`protocol.braid` so the public product policy owns the direct-vs-Braid choice.
