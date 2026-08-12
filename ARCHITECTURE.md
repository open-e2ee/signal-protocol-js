# OpenE2EE Signal Protocol SDK Architecture

> Navigation: [README](./README.md) | **ARCHITECTURE** | [ADAPTERS](./ADAPTERS.md) | [SECURITY](./docs/SECURITY.md) | [API Reference](./docs/api/README.md)

`@open-e2ee/signal-protocol-sdk` is a reusable, independently maintained package with a
versioned profile based on selected public Signal Protocol specifications. It
owns client-side encryption, local protocol state, prekey lifecycle,
multi-device session orchestration, group sender keys, sealed sender,
profile/username helpers, and explicit local/remote adapter seams. Public
security guarantees and protocol policy are documented in
[Security](./docs/SECURITY.md) and
[Protocol Policy](./docs/PROTOCOL_POLICY.md).

The `@open-e2ee` scope is the umbrella namespace. Package and primary-client
names identify the protocol they implement so future protocol packages do not
share an ambiguous client identity.

This package is pre-1.0. Prefer a clear, versioned correction over a
compatibility shim when a boundary is wrong.

## Review Posture

- Crypto and protocol internals must be auditable from current code, not historical layout names.
- Public APIs should be narrow and explicit. Platform and backend adapters live on subpaths.
- Runtime dependencies point inward toward lower protocol layers. Type-only imports are allowed where they describe ports or public contracts.
- Shared protocol strategy, reference-aligned limits, and HKDF info strings belong in `types/protocol-config.ts`, not in the client layer.
- Session record resolution belongs to `internal/session/session-resolver.ts`; SESAME orchestrates it but does not own the shared active/archive helper.

## Package Shape

| Area                    | Path                                                                                                                                                                   | Purpose                                                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Public API              | [client/](./client/)                                                                                                                                                   | `SignalProtocolClient`, config, high-level send/receive/session operations                                                 |
| Shared types            | [types/](./types/)                                                                                                                                                     | Protocol addresses, records, API contracts, protocol configuration                                                         |
| Session domain          | [internal/session/](./internal/session/)                                                                                                                               | Session establishment, session cipher, active/archive session resolution                                                   |
| Orchestration           | [internal/manager/](./internal/manager/), [internal/sesame/](./internal/sesame/)                                                                                       | Protocol manager and multi-device SESAME workflows                                                                         |
| Protocol algorithms     | [internal/protocol/](./internal/protocol/)                                                                                                                             | X3DH, PQXDH, Double Ratchet, Triple Ratchet, SPQR, sender keys, sealed sender, ZK helpers                                  |
| Crypto foundation       | [internal/crypto/](./internal/crypto/)                                                                                                                                 | X25519, Ed25519, ML-KEM, AES, HKDF, padding                                                                                |
| Key model               | [keys/](./keys/)                                                                                                                                                       | Key generation, branded key types, identity type helpers                                                                   |
| Public feature surfaces | [blocking/](./blocking/), [groups/](./groups/), [media/](./media/), [profile/](./profile/), [sealed-sender/](./sealed-sender/), [username/](./username/), [zk/](./zk/) | App-facing helpers that compose protocol, media, or account-state behavior without joining the inward dependency hierarchy |
| Public utility surfaces | [encoding/](./encoding/), [files/](./files/), [hooks/](./hooks/), [utils/](./utils/), `logger.ts`, `server-clock.ts`, `versions.ts`                                    | Stable helpers, React hooks, logging, clock estimation, version metadata, and file/encoding utilities                      |
| Local adapters          | [local/](./local/)                                                                                                                                                     | Local protocol stores and secret vault integrations                                                                        |
| Remote adapters         | [remote/](./remote/)                                                                                                                                                   | Relay and object-store ports plus Convex, in-memory, R2, and S3 adapters                                                   |
| Device features         | [device/](./device/)                                                                                                                                                   | Device IDs, provisioning, linked-device lifecycle and transfer                                                             |

## Documentation Ownership

This file is the package architecture hub. Root documentation covers package
entrypoints and operating guidance, while [docs/](./docs/) contains focused
guides and the generated [API reference](./docs/api/README.md). Source comments
own implementation-level invariants that are necessary to understand or safely
modify the code.

## Public Surface

The root package is core-only:

```ts
import {
  SignalProtocolClient,
  createSignalProtocolClient,
  ProtocolAddress,
  BraidPolicy,
  PostQuantumPolicy,
  keys,
  safety,
  encoding,
} from "@open-e2ee/signal-protocol-sdk";
```

Platform and backend integrations are explicit subpaths such as:

- `@open-e2ee/signal-protocol-sdk/local/store/expo`
- `@open-e2ee/signal-protocol-sdk/local/store/memory`
- `@open-e2ee/signal-protocol-sdk/remote/relay/convex`
- `@open-e2ee/signal-protocol-sdk/remote/relay/memory`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2/server`
- `@open-e2ee/signal-protocol-sdk/remote/object-store/s3`
- `@open-e2ee/signal-protocol-sdk/client/compose`
- `@open-e2ee/signal-protocol-sdk/device`
- `@open-e2ee/signal-protocol-sdk/types`

`internal/**` is implementation-only and application code should not import it.

## Layer Model

The executable layer map lives in [layers.ts](./layers.ts).

| Layer | Name              | Runtime directories                                            | Responsibility                                                    |
| ----- | ----------------- | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| 1     | API               | `client/`                                                      | Public client boundary and application-facing workflows           |
| 2     | Orchestration     | `internal/manager/`, `internal/sesame/`, `internal/groups/`    | Coordinate sessions, devices, groups, retries, relay/store ports  |
| 3     | Domain/Session    | `internal/session/`, `safety/`                                 | Session records, handshake, cipher, safety numbers                |
| 4     | Domain/Algorithms | `internal/protocol/`                                           | Key agreement, ratchets, sender keys, sealed sender, ZK protocols |
| 5     | Domain/Keys       | `keys/`                                                        | Key types and generation                                          |
| 6     | Domain/Crypto     | `internal/crypto/`                                             | Cryptographic primitives and low-level KDF/encryption helpers     |

Runtime imports must point inward, toward equal or higher layer numbers. For example, Layer 3 may import Layer 4, 5, or 6; Layer 4 must not import Layer 3.

Shared non-layer modules:

- `types/`: stable contracts used across layers. This is where protocol strategy config and protocol constants live.
- `encoding/` and `utils/`: package-level utility surfaces.
- `blocking/`, `files/`, `groups/`, `hooks/`, `profile/`, `sealed-sender/`, `username/`, and `zk/`: public feature surfaces that compose protocol, account, or app-facing behavior.
- `local/`, `remote/`, `device/`: adapter and device-integration packages composed at the API/orchestration boundary.

## Protocol Map

| Protocol       | Implementation                                                           | Spec notes                                      |
| -------------- | ------------------------------------------------------------------------ | ----------------------------------------------- |
| X3DH           | [internal/protocol/x3dh/](./internal/protocol/x3dh/)                     | Classical initial key agreement                 |
| PQXDH          | [internal/protocol/pqxdh/](./internal/protocol/pqxdh/)                   | Hybrid initial key agreement with ML-KEM-1024   |
| Double Ratchet | [internal/protocol/double-ratchet/](./internal/protocol/double-ratchet/) | EC ratchet, skipped keys, header encryption     |
| SPQR           | [internal/protocol/spqr/](./internal/protocol/spqr/)                     | Sparse post-quantum ratchet with ML-KEM-768     |
| Triple Ratchet | [internal/protocol/triple-ratchet/](./internal/protocol/triple-ratchet/) | Double Ratchet plus SPQR hybrid message keys    |
| SESAME         | [internal/sesame/](./internal/sesame/)                                   | Multi-device session management and convergence |
| Sender Keys    | [internal/protocol/sender-keys/](./internal/protocol/sender-keys/)       | Group message sender-key state                  |
| Sealed Sender  | [internal/protocol/sealed-sender/](./internal/protocol/sealed-sender/)   | Sender certificate and envelope privacy helpers |

## Configuration Ownership

`client/config.ts` owns application-facing client configuration: storage, relay,
object store, sealed sender, logging, hooks, and the product-facing protocol
policy fields `protocol.postQuantum` and `protocol.braid`.

The provider-neutral object-store port separates a retry/idempotency
`requestId`, the canonical `objectId` carried in encrypted pointers, and the
private provider key. The Convex R2 client entry calls app-owned public broker
functions. Its server-only sibling can register generic broker mechanics, but
the consuming app still owns the R2 component, authentication, authorization,
object records, credentials, and bucket.

`types/protocol-config.ts` owns protocol-domain configuration and constants shared by client, session, protocol, and adapters:

- `SignalProtocolConfig`
- `PostQuantumPolicy`
- `ProtocolStrategyConfig`
- `ProtocolSelectionEvent`
- `BraidProgressEvent`
- `SenderKeysConfig`
- `PreKeyMaintenanceStore`
- `SENDER_KEYS_DEFAULTS`
- `MAX_UNACKNOWLEDGED_SESSION_AGE_MS`
- `ARCHIVED_STATES_MAX_LENGTH`
- `PQXDH_INFO_DEFAULT`
- `X3DH_INFO_DEFAULT`
- SPQR limit and info-string resolvers

This boundary prevents lower protocol/session layers from depending on the client package.

Application code should prefer:

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

Strict post-quantum sessions and ML-KEM Braid are the defaults, so application
code should leave `protocol` unset unless the product has made an explicit
compatibility decision. Advanced strategy fields remain available for
diagnostics, telemetry, and algorithm tuning, but compatibility fallback is selected
through `protocol.postQuantum: 'compatible'`, and direct SPQR is selected
through `protocol.braid: 'disabled'`.

Two strategy hooks report protocol events. `onProtocolSelected` fires once per
session establishment, from the handshake. `onBraidProgress` fires on every
braid-mode send and receive, from the SPQR seam that holds the braid state; the
manager carries the strategy into `SessionCipher`, which passes it to `spqrSend`
and `spqrRecv`. Both hooks are guarded, so a consumer that throws cannot break
the protocol path.

## Session Resolution

Session convergence is a SESAME behavior, but active/archive record manipulation is shared session-domain logic.

- Owner: [internal/session/session-resolver.ts](./internal/session/session-resolver.ts)
- Consumed by: [internal/session/cipher.ts](./internal/session/cipher.ts) and [internal/sesame/manager.ts](./internal/sesame/manager.ts)
- Re-exported by: [internal/sesame/index.ts](./internal/sesame/index.ts) for existing internal SESAME imports

The resolver wraps `SessionRecord` helpers with metadata updates for:

- inserting a new active session while archiving the prior one,
- enumerating decrypt candidates in active-then-archive order,
- promoting an archived session after successful decryption,
- archiving the active session for retry/session reset flows.

## Data Flow

```text
Application
  |
  v
SignalProtocolClient (client/)
  |
  +-- local protocol state -> local/store/*
  +-- relay and blob ports -> remote/*
  |
  v
Orchestration (internal/manager, internal/sesame)
  |
  v
Session domain (internal/session)
  |
  v
Protocol algorithms (internal/protocol)
  |
  v
Keys and crypto (keys, internal/crypto)
```

Servers and object stores only see encrypted envelopes or encrypted objects. Decrypted content stays on the device.
