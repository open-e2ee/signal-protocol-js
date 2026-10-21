# Protocol Policy Guide

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) | [Security](./SECURITY.md) | [Getting Started](./GETTING_STARTED.md) | **Protocol Policy** | [Deviations](./DEVIATIONS.md)

This document covers **which protocol modes run** and which fail closed.
[Deviations](./DEVIATIONS.md) covers **how the profile differs from the
published specifications and from `libsignal`**. That includes the composite
identity, the Ed25519-instead-of-XEdDSA signature scheme, the ML-KEM Braid
`hek` operand order, and every other difference.

The public Signal Protocol client policy is:

<!-- doc-snippet:illustrative config-object-fragment -->
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

<!-- doc-snippet:skip requires-external-context -->
```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'required' },
});
```

Required mode means post-quantum session establishment and the post-quantum
message ratchet are mandatory. `'required'` is the only `postQuantum` value.

## No Classical Key Agreement

The SDK has no classical key agreement. Every new session uses PQXDH with
ML-KEM-1024. A peer that publishes no post-quantum prekeys fails closed with
`PQXDHRequiredError` (`PQXDH_REQUIRED`), and no session is stored.

No setting allows downgrade recovery:

- malformed post-quantum metadata fails closed
- cryptographic failure after post-quantum selection fails closed
- missing referenced local post-quantum prekey material fails closed
- successful post-quantum establishment keeps the post-quantum message ratchet
  mandatory

## Braid Policy

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
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

`'required'` is the only `postQuantum` value. Any other value throws
`Unsupported postQuantum policy` when the client is created.

## Advanced Telemetry

The advanced `protocolStrategy.onProtocolSelected` callback remains available
for diagnostics. It fires once for each session that PQXDH establishes. A peer
without post-quantum prekeys fails before selection, so the callback does not
fire for it.

The advanced `protocolStrategy.onBraidProgress` callback reports ML-KEM Braid
chunk progress after every braid-mode send and receive:

- the chunks this side carried in the current epoch
- the chunks the open transfers account for
- the epoch
- whether the operation produced the epoch secret

A direct-mode session never raises it.

Do not set `protocolStrategy.sckaMode` when `protocol` sets more than
`contentRecovery`. Use `protocol.braid` so the public product policy owns the
direct-vs-Braid choice.

## Content Recovery

A device that cannot decrypt a message asks the sender for it again with a
retry request. To answer with the content, the sender keeps the plaintext of
each resendable message in its local store. `protocol.contentRecovery`
decides whether the store may hold that plaintext.

<!-- doc-snippet:illustrative config-object-fragment -->
```ts
protocol: {
  contentRecovery: {
    mode: 'require-protected',
    retentionMs: 14 * 24 * 60 * 60 * 1000,
    isCurrentMember: async (groupId, userId) => true,
  },
}
```

The client reads the `protection` that the local store declares and derives
a level:

| Level | Store protection | Built-in stores |
| --- | --- | --- |
| `protected` | Encrypted, with the key in an operating system keychain or a declared application vault | SQLite and key-value stores with a keychain or application vault |
| `co-located` | Encrypted, with the key in storage that the data shares | `IndexedDbSignalProtocolStore`, and the web SQLite store with the IndexedDB vault |
| `none` | No encryption or no key | `InMemorySignalProtocolStore`, and a SQLite store with `encryptionAtRest: false` |

The `co-located` stores encrypt their data. `IndexedDbSignalProtocolStore`
encrypts each record and each metadata value with AES-256-GCM. Its key is in
the same database. The web SQLite store encrypts its whole file. That is weaker
key custody, not missing encryption. A reader of the origin storage can also
read the key. Metadata key names stay in clear text in
`IndexedDbSignalProtocolStore`.

The modes:

- `require-protected`, the default, keeps content only at the `protected`
  level.
- `allow-co-located-key` also keeps content at the `co-located` level. Use it
  only after a product review accepts that key custody.
- `off` keeps no content.

A `none` level never keeps content. When the policy refuses the store, the
client keeps no pairwise message record and no send log entry, and deletes
the ones that the store already holds. A retry request for a direct message
then resets the session with no content. The client shows the decision in
`client.contentRecoveryStatus`, with `reason` when it is off, and logs it
once at creation.

The client keeps content for 14 days from the time that it first stored it.
A retry does not extend that time. Signal uses the same default:
`retryRespondMaxAge` on Android and `messageSendLogEntryLifetime` on iOS are
both 14 days. `retentionMs` sets another value, at most 30 days. A message
that the Relay delivers after the retention may have no resendable content.

The client deletes expired content before each send log lookup, at creation,
at `stop()`, and before the first resendable group send of each day. An E2EE
delivery receipt from a device deletes the send log row of that device, and
the last row takes the content with it. A Relay delivery receipt, a read
receipt, and a viewed receipt delete no row. A device also acknowledges a
copy that it could not decrypt, so the Relay receipt does not prove that the
device has the content. `client.getPendingRecipients(clientMessageId)` lists
the devices that still have a row. `client.forgetSentContent(clientMessageId)`
deletes the content of one group send at once. It does not delete the
pairwise message records. A device lifecycle reset clears the send log with
the other local crypto state.

Before the sender gives group content again, it checks a group membership
source. Configure `groups` with `resolveAciBytesByUserIds` for managed
groups, or set `isCurrentMember` for ad hoc groups. The client checks a
managed group against its verified group state and never asks the hook
about it. The hook gets the prefixed group ID that `createGroupId` makes.
`contentRecoveryStatus.groupMembershipSource` is `managed`, `hook`, or
`none`. A client with no source still keeps content and logs one warning
at creation. With no source for a group, the sender gives no group content
again. A direct message resend needs no source.

A group send of a `DataMessage` has the content hint `Resendable` when the
policy keeps content and the application sets no other hint. The client
writes the content and the recipient devices to the send log before it
stores the outgoing intent, so a failed write stops the send. When the
policy keeps no content, the send goes out as `Default`.

A custom store must declare its `protection` as `{ atRest, keyCustody }`.
The client validates the declaration and fails creation on a missing or
unknown value. A declaration adds no encryption. It must state what the
store does.
