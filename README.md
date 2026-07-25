<img src="https://raw.githubusercontent.com/open-e2ee/design/v0.2.2/brand/generated/open-e2ee-mark-adaptive.svg" alt="OpenE2EE" width="72" height="72">

# OpenE2EE Signal Protocol SDK

**End-to-end encrypted messaging for TypeScript apps. Signal Protocol, post-quantum by default, runs in Expo.**

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-2f6f5e)](https://github.com/open-e2ee/signal-protocol-js/blob/main/LICENSE)
[![Types: TypeScript](https://img.shields.io/badge/types-TypeScript-3178c6)](https://www.typescriptlang.org/)
[![npm version](https://img.shields.io/npm/v/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![npm downloads](https://img.shields.io/npm/dw/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2f6f5e)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk#provenance)
[![Checks](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml/badge.svg)](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/open-e2ee/signal-protocol-js/badge)](https://scorecard.dev/viewer/?uri=github.com/open-e2ee/signal-protocol-js)

*Not affiliated with Signal Messenger.* This is an independent implementation of the public Signal Protocol specifications — full notice in [NOTICE](https://github.com/open-e2ee/signal-protocol-js/blob/main/NOTICE). It is **not wire-compatible with Signal Messenger or libsignal**: messages, identities, and safety numbers do not interoperate, and every deliberate difference is documented in [DEVIATIONS](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md).

[Docs](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/GETTING_STARTED.md) ·
[Quick Start](#quick-start) ·
[Architecture](https://github.com/open-e2ee/signal-protocol-js/blob/main/ARCHITECTURE.md) ·
[Security Model](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/SECURITY.md) ·
[Protocol Policy](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/PROTOCOL_POLICY.md) ·
[Deviations](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md)

---

- **Pure TypeScript.** No native modules, no prebuild step, no platform binaries to ship.
- **Runs where your app runs.** Expo, React Native, modern browsers, and Node from one package.
- **Post-quantum by default.** PQXDH and ML-KEM session establishment are on without configuration, and fail closed.
- **Real messaging features.** Multi-device, groups, sealed sender, encrypted attachments, safety numbers.
- **Pluggable storage and relay.** Device-local storage is required and yours; the relay is an interface, not a hosted service.
- **AGPL-3.0-or-later, or a commercial license.** Building something closed-source? Email licensing@open-e2ee.dev.

`0.1.0-alpha.2` — public APIs and persisted formats may change before `1.0`.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

Installing straight from the repository also works — the package compiles itself during install, so TypeScript is the only build requirement:

```bash
npm install github:open-e2ee/signal-protocol-js
```

Adapters declare their runtime requirements as optional peer dependencies, so install the ones your chosen adapters need (for example `expo-sqlite` and `expo-secure-store`, or `convex`).

## Quick Start

Two clients, one process, no account and no server. The relay holds the envelope; only Bob's device turns it back into text.

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";

const relay = mockRelay();
await relay.registerDevice("alice", { encryptedDeviceName: new ArrayBuffer(0) });
await relay.registerDevice("bob", { encryptedDeviceName: new ArrayBuffer(0) });

const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore(), relay },
});
const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: mockStore(), relay },
});

await alice.syncToServer();
await bob.syncToServer();

// Decrypted content reaches your app here, and nowhere else.
bob.registerHook("onMessageDecrypted", async (message) => {
  console.log(`${message.senderId}: ${message.content}`); // alice: hello
});

await alice.send("bob", "hello");   // the relay now holds ciphertext and metadata
bob.startRelaySubscription();       // delivery and local decryption start here
```

Every identifier above is a real export. This exact block is extracted from this README and executed against the packed package by [this repository's CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) on every change, and the same sequence runs in the engineering repository's automated checks.

Next: [inspect what the relay actually stored](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/GETTING_STARTED.md), then compose the [Expo + Convex production client](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/CLIENT_COMPOSITION.md).

## How it compares

Measured from the GitHub and npm registry APIs on 2026-07-24. Every alternative is a real project doing a real job; the axes below are the ones this SDK was built to change, not a general quality ranking.

| | Expo / React Native | Browser | Maintained | Post-quantum | TypeScript-native | Commercial license |
|---|---|---|---|---|---|---|
| **`@open-e2ee/signal-protocol-sdk`** | Yes | Yes (browser store is experimental) | Yes — `0.1.0-alpha`, active | Yes — PQXDH + ML-KEM, default and fails closed | Yes | Yes |
| [`@signalapp/libsignal-client`](https://github.com/signalapp/libsignal) | No — prebuilt native binaries for Windows, macOS, and Linux only | No | Yes — very active | Yes | No — Rust core with TypeScript bindings | No (AGPL-3.0 only) |
| [`libsignal-protocol-javascript`](https://github.com/signalapp/libsignal-protocol-javascript) | No | Yes | No — archived, last push 2021-08-04 | No | No — JavaScript | No (GPL-3.0) |
| [`@privacyresearch/libsignal-protocol-typescript`](https://github.com/privacyresearchgroup/libsignal-protocol-typescript) | No documented React Native path | Yes | No — last npm publish 2023-05-06, last repo push 2023-07-18 | No | Yes | No (GPL-3.0) |
| [`ts-mls`](https://github.com/LukaJCB/ts-mls) | Yes | Yes | Yes — very active | Yes | Yes | No (MIT) |

`ts-mls` implements [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html), a different protocol with different properties — if MLS suits your product, it is a good library and this table is not an argument against it. `@signalapp/libsignal-client` is the implementation Signal Messenger itself uses; its README states that use outside Signal is unsupported.

## Trust and verification

Cryptography deserves evidence rather than adjectives, so here is what there is and what there is not.

**Audit status.** Not yet audited. An independent review is planned; no firm is engaged and no date is set. Nothing here should be read as a third-party assurance claim.

**Security model and protocol policy.** The [security model](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/SECURITY.md) states the threat model, what is in and out of scope, the storage boundary, and the resource limits. The [protocol policy](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/PROTOCOL_POLICY.md) states which protocol modes are supported and which fail closed.

**Specifications, pinned by revision.** The implementation follows its own versioned profile based on these published specifications:

| Specification | Revision |
|---|---|
| [X3DH](https://signal.org/docs/specifications/x3dh/) | Revision 1, 2016-11-04 |
| [PQXDH](https://signal.org/docs/specifications/pqxdh/) | Revision 3, 2023-05-24 (last updated 2024-01-23) |
| [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) | Revision 4, 2025-11-04 |
| [Sesame](https://signal.org/docs/specifications/sesame/) | Revision 2, 2017-04-14 |
| [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) | Revision 1, 2025-02-21 (last updated 2025-09-26) |
| [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) | Final, 2024-08-13 |
| [RFC 8032 (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032.html) | — |

**Not wire-compatible, and specific about why.** This SDK cannot exchange messages with Signal Messenger or `libsignal`, cannot exchange identities with them, and its safety numbers will never match the ones a Signal client displays for the same two users. The cryptographic core is the same; the wire profile is deliberately its own. Identities are a versioned composite of separate X25519 and Ed25519 keys rather than one Curve25519 key, so signatures are ordinary RFC 8032 Ed25519 rather than XEdDSA; ML-KEM-1024 keys and ciphertexts are tagged `0x0A`, distinct from the round-3 Kyber1024 `0x08` tag. [DEVIATIONS](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md) is the complete account — every difference from the specifications and from `libsignal`, with the reason, the cost, and the file that implements it. The threat model boundary is in the [security model](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/SECURITY.md).

**Dependencies: 7.** Seven direct production dependencies — `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `async-lock`, `protobufjs`, `unique-names-generator` — resolving to 8 packages in total, the eighth being `long` by way of `protobufjs`. Everything else in the tree is a development or optional peer dependency.

**Automated checks.** The published repository is a mechanized export of a private engineering repository, filtered by an allowlist; the automated checks live there and have to pass before an export is cut. The most recent full run, on 2026-07-24, was 351 modules and 5,875 assertions, all passing (1 skipped). The [assurance summary](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ASSURANCE.md) explains what those cover, what is not published, and why. The published repository runs its own build, typecheck, and production dependency audit in [CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) on every change.

**Constant-time posture, honestly.** JavaScript engines offer no machine-level constant-time contract, and this SDK cannot invent one. What exists is best-effort source-level work on selected paths: full-scan comparison for equal-length MACs and identity bytes, fixed-work derivation of both decapsulation candidates before masked selection, and equal-work rejection padding on selected replay and authentication paths. These are not timing-equivalence proofs. Secret-influenced remainder and compression arithmetic remains, and JIT compilation, allocation, garbage collection, and cache effects stay observable. `secureZeroBytes()` overwrites the exact typed array it is handed and nothing more — not copies, not strings, not engine temporaries. The threat model does not cover hostile same-process code or a high-assurance co-resident timing adversary, and it says so.

**Reporting a vulnerability.** Email security@open-e2ee.dev rather than opening an issue. Acknowledgment within 48 hours, initial assessment within 7 days; the full policy is in [SECURITY.md](https://github.com/open-e2ee/signal-protocol-js/blob/main/SECURITY.md).

## Documentation

- [Getting Started](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/GETTING_STARTED.md) — installation, mental model, first working client.
- [Package Surface](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/PACKAGE_SURFACE.md) — root exports, every subpath, adapter implementations, core concepts.
- [Recipes](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/RECIPES.md) — message flow, protocol policy, multi-device, attachments, usernames.
- [Client Composition](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/CLIENT_COMPOSITION.md) — production composition with Expo and Convex.
- [Architecture](https://github.com/open-e2ee/signal-protocol-js/blob/main/ARCHITECTURE.md) and [Adapters](https://github.com/open-e2ee/signal-protocol-js/blob/main/ADAPTERS.md) — layer model and composition boundaries.
- [Integration Interfaces](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/INTERFACES.md) — the interfaces to implement for custom storage, vaults, relays, and object stores.
- [Error Handling](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ERROR_HANDLING.md) and [Troubleshooting](https://github.com/open-e2ee/signal-protocol-js/blob/main/TROUBLESHOOTING.md).
- [E2EE concepts](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/E2EE.md) — what changes about your architecture when the relay cannot read.
- [Deviations](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md) — every difference from the Signal Protocol specifications and from `libsignal`, with reasons and costs.
- [API Reference](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/api/README.md) — generated from the exported declarations.

## License and warranty

Licensed under `AGPL-3.0-or-later`; see [LICENSE](https://github.com/open-e2ee/signal-protocol-js/blob/main/LICENSE). For proprietary products that cannot meet AGPL obligations, commercial licensing is available at licensing@open-e2ee.dev.

The software is provided **as is**, without warranties or conditions of any kind. To the extent permitted by applicable law, copyright holders and contributors are not liable for damages arising from its use. Applications remain responsible for evaluating this SDK against their own requirements and for securing their deployment, storage, authentication, authorization, and operations. This summary does not modify the license; the complete warranty disclaimer and limitation of liability are in sections 15 and 16 of the GNU Affero General Public License.
