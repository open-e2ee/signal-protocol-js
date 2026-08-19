<img src="https://raw.githubusercontent.com/open-e2ee/design/v0.8.0/brand/generated/open-e2ee-mark-adaptive.svg" alt="OpenE2EE" width="72" height="72">

# OpenE2EE Signal Protocol SDK

**End-to-end encrypted messaging for TypeScript apps. Signal Protocol, post-quantum by default, runs in Expo.**

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-2f6f5e)](https://github.com/open-e2ee/signal-protocol-js/blob/main/LICENSE)
[![npm version](https://img.shields.io/npm/v/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![native crypto: 0](https://img.shields.io/badge/native_crypto-0-2f6f5e)](./ARCHITECTURE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2f6f5e)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk#provenance)
[![Checks](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml/badge.svg)](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml)

[Website](https://open-e2ee.dev) ·
[Documentation](https://docs.open-e2ee.dev) ·
[Live demo](https://open-e2ee.dev/#demo) ·
[API reference](https://docs.open-e2ee.dev/reference/api) ·
[Security](./SECURITY.md)

- **One TypeScript package.** Run the same protocol code in Expo, React Native, modern browsers, and Node.
- **Post-quantum by default.** The default policy requires PQXDH session establishment and the ML-KEM Braid post-quantum ratchet. Required post-quantum operations fail closed.
- **Messaging primitives included.** Build multi-device messaging, groups, sealed sender, encrypted attachments, and safety-number verification.
- **Your infrastructure, behind explicit interfaces.** Your application owns device-local storage. The relay is an interface, not a hosted service. The relay never needs message plaintext or device private keys.
- **AGPLv3, or a commercial license.** Proprietary applications that cannot meet AGPLv3 obligations can use a [commercial license](./COMMERCIAL.md).

The protocol code ships without a native crypto module or platform crypto binary. The Expo SQLCipher store requires a development build and native project configuration.

Version `0.4.x`. Public APIs and persisted formats can change before `1.0`.

OpenE2EE implements a versioned profile of the published Signal Protocol specifications. It is not affiliated with Signal Messenger and is **not wire-compatible with Signal Messenger or libsignal**. Messages, identities, and safety numbers do not interoperate. Read the [full notice](./NOTICE) and [documented deviations](./docs/DEVIATIONS.md).

## See an encrypted round trip

[![Two devices exchange an end-to-end encrypted message through a relay. The relay handles public prekeys and ciphertext. Only the receiving device displays the plaintext.](https://raw.githubusercontent.com/open-e2ee/signal-protocol-js/main/docs/assets/demo/encrypted-round-trip.gif)](https://open-e2ee.dev/#demo)

The [live demo](https://open-e2ee.dev/#demo) runs two SDK clients against an in-memory relay. On desktop, type a message and inspect the envelope, ratchets, relay mailbox, and decrypted result. On mobile, the same protocol run replays at reading pace. The protocol and cryptography are real. The example simulates infrastructure in memory. Displayed timings exclude network time.

## Install

Requires Node 18 or later for the local example.

```bash
npm install @open-e2ee/signal-protocol-sdk
```

## Run a local encrypted round trip

Save this as `quickstart.mjs`, then run `node quickstart.mjs`. It uses development-only in-memory adapters so that you can prove the message flow without a backend project.

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

const delivered = new Promise((resolve) => {
  bob.registerHook("onMessageDecrypted", async (message) => {
    console.log(`${message.senderId}: ${message.content}`);
    bob.stopRelaySubscription();
    resolve(undefined);
  });
});

await alice.send("bob", "hello");
bob.startRelaySubscription();
await delivered;
```

Expected output:

```text
alice: hello
```

The client factory creates or loads each device identity. When given a relay, it also publishes the public prekey bundle. `send()` fetches Bob's bundle and starts the required post-quantum session. It then gives ciphertext plus routing metadata to the relay. Bob's subscription retrieves and decrypts the envelope on his device.

The in-memory store loses identities, sessions, and ratchet state on restart. The in-memory relay has no authentication, authorization, or durable storage. Do not ship either adapter. Continue with the [hosted Quickstart](https://docs.open-e2ee.dev/start/quickstart), which explains key custody, relay metadata, prekey replenishment, additional devices, and recovery policy.

## Move to production storage

Choose the device-local store for your runtime, then supply a relay that authenticates each device and implements your product's access policy.

| Runtime | Storage path | Deployment boundary |
|---|---|---|
| Expo | [`expoStore`](./local/store/expo/README.md) | Configure SQLCipher before schema access. Requires a development build; it does not run in Expo Go. |
| Browser | [`indexedDbStore`](./local/store/web/README.md) | IndexedDB persists encrypted records, but same-origin JavaScript can access the records and their key. Review CSP, XSS, dependencies, and service workers. |
| Bare React Native | [`reactNativeStore`](./local/store/react-native/README.md) | Provide an atomic, durable key-value backend and run the exported backend conformance kit. |
| Node | [`nodeStore`](./local/store/node/README.md) | Set an explicit private data directory on a trusted local filesystem. |

The [adapter guide](./ADAPTERS.md) defines every storage, relay, vault, and object-store boundary. The [client composition guide](./docs/CLIENT_COMPOSITION.md) shows an Expo and Convex integration.

## Security and assurance

The [assurance summary](./docs/ASSURANCE.md) states what the automated checks cover and what the public export does not contain. Public CI rebuilds, type-checks, audits, and runs this README example against the packed package.

JavaScript engines do not provide a machine-level constant-time contract or guaranteed zeroization. The [security model](./docs/SECURITY.md) defines the timing, same-process, storage, and metadata boundaries. The [protocol policy](./docs/PROTOCOL_POLICY.md) defines supported modes and fail-closed behavior.

Report a suspected vulnerability privately through the process in [SECURITY](./SECURITY.md). Do not open a public issue for it.

## Why developers choose this SDK

The SDK gives TypeScript applications one maintained package for required post-quantum session establishment and ratcheting, multi-device messaging, groups, sealed sender, attachments, and safety numbers. It keeps protocol state on the device and leaves the relay implementation to the application.

[Compare maintained alternatives and their limits.](https://open-e2ee.dev/product/#how-it-compares)

## Documentation

- [Getting started](./docs/GETTING_STARTED.md): the integration sequence and mental model.
- [Package surface](./docs/PACKAGE_SURFACE.md): root exports, subpaths, adapters, and core concepts.
- [Recipes](./docs/RECIPES.md): messaging, multi-device, attachments, and usernames.
- [Architecture](./ARCHITECTURE.md) and [adapters](./ADAPTERS.md): layer ownership and composition boundaries.
- [Integration interfaces](./docs/INTERFACES.md): contracts for custom stores, vaults, relays, and object stores.
- [Error handling](./docs/ERROR_HANDLING.md) and [troubleshooting](./TROUBLESHOOTING.md).
- [Deviations](./docs/DEVIATIONS.md): differences from the specifications and libsignal, with reasons and costs.
- [Hosted API reference](https://docs.open-e2ee.dev/reference/api): exported types and methods.

## Help and contributing

Open a [bug report](https://github.com/open-e2ee/signal-protocol-js/issues/new?template=bug_report.yml) or send [API and documentation feedback](https://github.com/open-e2ee/signal-protocol-js/issues/new?template=api_feedback.yml). Read [CONTRIBUTING](./CONTRIBUTING.md) before you propose code. Use the private process in [SECURITY](./SECURITY.md) for suspected vulnerabilities.

## License and warranty

Licensed under AGPLv3 (`AGPL-3.0-or-later`). See [LICENSE](./LICENSE). A [commercial license](./COMMERCIAL.md) covers proprietary products that cannot meet AGPLv3 obligations.

The license provides the software **as is**, without warranties or conditions of any kind. To the extent that applicable law permits, copyright holders and contributors are not liable for damages that arise from its use. Your application must evaluate the SDK against its requirements and secure its deployment, storage, authentication, authorization, and operations. This summary does not modify the license.
