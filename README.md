<img src="https://raw.githubusercontent.com/open-e2ee/design/v0.8.0/brand/generated/open-e2ee-mark-adaptive.svg" alt="OpenE2EE" width="72" height="72">

# OpenE2EE Signal Protocol SDK

**End-to-end encrypted messaging for TypeScript apps. Signal Protocol, post-quantum by default, runs in Expo.**

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-2f6f5e)](https://github.com/open-e2ee/signal-protocol-js/blob/main/LICENSE)
[![Types: TypeScript](https://img.shields.io/badge/types-TypeScript-3178c6)](https://www.typescriptlang.org/)
[![npm version](https://img.shields.io/npm/v/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![native modules: 0](https://img.shields.io/badge/native_modules-0-2f6f5e)](https://github.com/open-e2ee/signal-protocol-js/blob/main/ARCHITECTURE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2f6f5e)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk#provenance)
[![Checks](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml/badge.svg)](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/open-e2ee/signal-protocol-js/badge)](https://scorecard.dev/viewer/?uri=github.com/open-e2ee/signal-protocol-js)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14043/badge)](https://www.bestpractices.dev/projects/14043)

[Website](https://open-e2ee.dev) ·
[Docs](https://docs.open-e2ee.dev) ·
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
- **Pluggable storage and relay.** Your application owns the required device-local storage. The relay is an interface, not a hosted service.
- **AGPLv3, or a commercial license.** Building something closed-source? See [COMMERCIAL](https://github.com/open-e2ee/signal-protocol-js/blob/main/COMMERCIAL.md).

*Not affiliated with Signal Messenger.* This package implements the public Signal Protocol specifications independently. [NOTICE](https://github.com/open-e2ee/signal-protocol-js/blob/main/NOTICE) carries the full notice. It is **not wire-compatible with Signal Messenger or libsignal**. Messages, identities, and safety numbers do not interoperate, and [DEVIATIONS](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md) documents every deliberate difference.

Version `0.3.x`. Public APIs and persisted formats may change before `1.0`.

## See it run

[![Linking a second device on the demo page. The scenario runs, then reports what each device can read. The device that was already there holds both messages. The newly linked device holds only the message sent after it existed.](https://raw.githubusercontent.com/open-e2ee/signal-protocol-js/main/docs/assets/demo/second-device.gif)](https://open-e2ee.dev/demo/#add-a-second-device)

The demo links a second device to an account over the real QR handshake. That device does not hold the message sent before it existed. No policy withholds the message. The device cannot read it, because the device's keys did not exist when the sender encrypted it.

The recording comes from [open-e2ee.dev/demo](https://open-e2ee.dev/demo). That page runs this package in the browser against the in-memory store and the in-memory relay. The protocol and the cryptography are real, and the adapters simulate the infrastructure in memory. Every scenario there prints the receiving device's own log, unedited.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

Installing straight from the repository also works. The package compiles itself during install, so TypeScript is the only build requirement:

```bash
npm install github:open-e2ee/signal-protocol-js
```

Adapters declare their runtime requirements as optional peer dependencies, so install the ones your chosen adapters need (for example `expo-sqlite` and `expo-secure-store`, or `convex`).

## Quick Start

Two clients, one process, no account and no server. The relay holds the envelope. Only Bob's device turns it back into text.

<!-- doc-snippet:run readme-quick-start expect="alice: hello" -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";

const relay = inMemoryRelay();
await relay.registerDevice("alice", { encryptedDeviceName: new ArrayBuffer(0) });
await relay.registerDevice("bob", { encryptedDeviceName: new ArrayBuffer(0) });

const alice = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: inMemoryStore(), relay },
});
const bob = await createSignalProtocolClient({
  identity: { userId: "bob" },
  adapters: { storage: inMemoryStore(), relay },
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

Every identifier above is a real export. [This repository's CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) extracts this exact block from this README and runs it against the packed package on every change. The same sequence runs in the engineering repository's automated checks.

Next: [inspect what the relay actually stored](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/GETTING_STARTED.md), then compose the [Expo + Convex production client](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/CLIENT_COMPOSITION.md).

## How it compares

Measured on 2026-08-03, these figures come from the GitHub API, the npm registry API, and the published package tarballs. Every alternative is a real project that does a real job. The axes below are the ones this SDK sets out to change, not a general quality ranking.

| | Expo / React Native | Browser | Maintained | Post-quantum | TypeScript-native | Commercial license |
|---|---|---|---|---|---|---|
| **`@open-e2ee/signal-protocol-sdk`** | Yes | Yes | Yes — `0.3.x`, active | Key agreement yes — PQXDH + ML-KEM, default and fails closed. Signatures no — identities are classical Ed25519 | Yes | Yes |
| [`@signalapp/libsignal-client`](https://github.com/signalapp/libsignal) | No — Node native addon; the 0.99.3 tarball ships binaries for macOS, Linux, and Windows only | No | Yes — very active; repo push 2026-07-31 | Key agreement yes | No — Rust core with TypeScript bindings | No (AGPL-3.0 only) |
| [`libsignal-protocol-javascript`](https://github.com/signalapp/libsignal-protocol-javascript) | No | Yes | No — archived, last push 2021-08-04 | No | No — JavaScript | No (GPL-3.0) |
| [`@privacyresearch/libsignal-protocol-typescript`](https://github.com/privacyresearchgroup/libsignal-protocol-typescript) | No documented React Native path | Yes | No — last npm publish 2023-05-06, last repo push 2023-07-18 | No | Yes | No (GPL-3.0) |
| [`ts-mls`](https://github.com/LukaJCB/ts-mls) | Not stated — browsers, Node, and serverless are the documented targets | Yes | Yes — very active; repo push 2026-08-03 | Key agreement and signatures — ML-KEM and ML-DSA-87 ciphersuites | Yes | Not needed (MIT) |

`ts-mls` implements [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html). That is a different protocol with different properties. If MLS suits your product, `ts-mls` is a good library, and this table is not an argument against it. Its post-quantum coverage also reaches further than this SDK's.

`@signalapp/libsignal-client` is the implementation Signal Messenger itself uses. Its README states that it does not support use outside Signal Messenger. Reach for it first when you ship a desktop or server application on Node.

The longer version of this table, with a paragraph on each project, is at [open-e2ee.dev/compare](https://open-e2ee.dev/compare).

## Trust and verification

Cryptography deserves evidence rather than adjectives, so here is what there is and what there is not.

**Audit status.** Adversarial AI agents review this SDK continuously. No independent firm audits it. Every change passes an adversarial AI review before it merges, and recurring whole-codebase AI audit passes run against the engineering repository. The [assurance summary](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ASSURANCE.md) states what that covers and what it does not. The SDK has no independent audit and no audit engagement. Read nothing here as a third-party assurance claim.

**Security model and protocol policy.** The [security model](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/SECURITY.md) states the threat model and the scope boundary. It also states the storage boundary and the resource limits. The [protocol policy](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/PROTOCOL_POLICY.md) states which protocol modes the SDK supports and which fail closed.

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

**Not wire-compatible, and specific about why.** This SDK cannot exchange messages or identities with Signal Messenger or `libsignal`. Its safety numbers will never match the ones a Signal Messenger client displays for the same two users. The cryptographic core is the same. The wire profile is deliberately its own.

Identities are a versioned composite of separate X25519 and Ed25519 keys rather than one Curve25519 key. Signatures are therefore ordinary RFC 8032 Ed25519 rather than XEdDSA. ML-KEM-1024 keys and ciphertexts carry the tag `0x0A`, which differs from the round-3 Kyber1024 tag `0x08`. [DEVIATIONS](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md) is the complete account. It names every difference from the specifications and from `libsignal`, with the reason, the cost, and the file that implements it. The [security model](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/SECURITY.md) holds the threat model boundary.

**Dependencies: 6.** The package has six direct production dependencies: `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `async-lock`, and `unique-names-generator`. They resolve to 6 packages in total. The only transitive edges run between the `@noble` packages, so the resolved tree adds nothing the list above does not already name. Everything else in the tree is a development or optional peer dependency.

**Automated checks.** The published repository is a mechanized export of a private engineering repository, through an allowlist. The automated checks live in that engineering repository, and they must pass before the export runs. The [assurance summary](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ASSURANCE.md) carries the current run figures and explains what the checks cover, what stays unpublished, and why. Every release regenerates those figures from a real run, and no one hand-edits them. The published repository runs its own build, typecheck, and production dependency audit in [CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) on every change.

**Constant-time posture, honestly.** JavaScript engines offer no machine-level constant-time contract, and this SDK cannot invent one. Selected paths carry best-effort source-level work:

- a full scan when it compares equal-length MACs and identity bytes
- fixed work on both decapsulation candidates, then a masked choice between them
- equal-work rejection padding on selected replay and authentication paths

These are not timing-equivalence proofs. Secret-influenced remainder and compression arithmetic remains. JIT compilation, allocation, garbage collection, and cache effects stay observable. `secureZeroBytes()` overwrites the exact typed array the caller hands it and nothing more. It does not touch copies, strings, or engine temporaries. The threat model does not cover hostile same-process code or a high-assurance co-resident timing adversary, and it says so.

**Reporting a vulnerability.** Email security@open-e2ee.dev rather than opening an issue. Acknowledgment within 72 hours, initial assessment within 7 days. [SECURITY.md](https://github.com/open-e2ee/signal-protocol-js/blob/main/SECURITY.md) carries the full policy.

## Documentation

Hosted guides, quickstarts per runtime, and concept docs live at
[docs.open-e2ee.dev](https://docs.open-e2ee.dev). The in-repo references below
carry the same version as the code:

- [Getting Started](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/GETTING_STARTED.md): installation, mental model, first working client.
- [Package Surface](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/PACKAGE_SURFACE.md): root exports, every subpath, adapter implementations, core concepts.
- [Recipes](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/RECIPES.md): message flow, protocol policy, multi-device, attachments, usernames.
- [Client Composition](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/CLIENT_COMPOSITION.md): production composition with Expo and Convex.
- [Architecture](https://github.com/open-e2ee/signal-protocol-js/blob/main/ARCHITECTURE.md) and [Adapters](https://github.com/open-e2ee/signal-protocol-js/blob/main/ADAPTERS.md): layer model and composition boundaries.
- [Integration Interfaces](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/INTERFACES.md): the interfaces to implement for custom storage, vaults, relays, and object stores.
- [Error Handling](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/ERROR_HANDLING.md) and [Troubleshooting](https://github.com/open-e2ee/signal-protocol-js/blob/main/TROUBLESHOOTING.md).
- [E2EE concepts](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/E2EE.md): what changes about your architecture when the relay cannot read.
- [Deviations](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/DEVIATIONS.md): every difference from the Signal Protocol specifications and from `libsignal`, with reasons and costs.
- [API Reference](https://github.com/open-e2ee/signal-protocol-js/blob/main/docs/api/README.md): generated from the exported declarations.

## License and warranty

Licensed under `AGPL-3.0-or-later`. See [LICENSE](https://github.com/open-e2ee/signal-protocol-js/blob/main/LICENSE). A commercial license covers proprietary products that cannot meet AGPLv3 obligations. See [COMMERCIAL](https://github.com/open-e2ee/signal-protocol-js/blob/main/COMMERCIAL.md) or email licensing@open-e2ee.dev.

The license provides the software **as is**, without warranties or conditions of any kind. To the extent that applicable law permits, copyright holders and contributors are not liable for damages that arise from its use. Your application must evaluate this SDK against its own requirements. It must also secure its own deployment, storage, authentication, authorization, and operations. This summary does not modify the license. Sections 15 and 16 of the GNU Affero General Public License carry the complete "Disclaimer of Warranty" and "Limitation of Liability" text.
