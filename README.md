<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/open-e2ee/design/v0.21.2/brand/generated/hosted/open-e2ee-logo-dark.svg">
  <img src="https://raw.githubusercontent.com/open-e2ee/design/v0.21.2/brand/generated/hosted/open-e2ee-logo-light.svg" alt="OpenE2EE" width="340">
</picture>

# OpenE2EE Signal Protocol SDK

**Pure TypeScript for end-to-end encrypted chat.**

Add encrypted messaging to Expo, React Native, browser, and Node applications. The SDK manages device identities, session establishment, and message encryption. Your application supplies storage, user authentication, and a relay for delivery.

The default policy requires post-quantum session establishment and ratcheting. The protocol implementation is open source under the MIT License or the Apache License 2.0, at your option.

[**Run an encrypted exchange in your browser**](https://open-e2ee.dev/playground) · [Edit on StackBlitz](https://stackblitz.com/fork/github/open-e2ee/signal-protocol-js/tree/v3.0.0/examples/browser) · [Run on Expo / Hermes](./examples/expo/README.md)

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-2f6f5e)](./LICENSE)
[![npm version](https://img.shields.io/npm/v/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2f6f5e)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk#provenance)
[![Checks](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml/badge.svg)](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml)

[Documentation](https://docs.open-e2ee.dev) · [API reference](https://docs.open-e2ee.dev/reference/api) · [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay) · [Security](./SECURITY.md)

## See an encrypted round trip

Press play for device setup, session establishment, encrypted delivery, and decryption on each device.

https://github.com/user-attachments/assets/d8002bc3-c037-41b6-8f48-4008f2d49e6c

The [visual demo](https://open-e2ee.dev/#demo) shows the envelope, ratchets, relay mailbox, and decrypted result. On desktop, type a message and inspect each step. On mobile, a recorded protocol run replays at reading pace. Displayed timings exclude network time.

The [console example](https://open-e2ee.dev/playground) executes in your browser on desktop or mobile. It creates Alice and Bob, sends your message, and decrypts a reply. The page and developer console show the actual output. [Read the complete source](./examples/browser/src/exchange.ts) or [run it locally](./examples/browser/README.md).

Both examples use real protocol code and cryptography. An in-memory relay holds their envelopes. They need no account or backend project.

## What the SDK handles

- **Session establishment and ratcheting.** PQXDH establishes sessions. The ML-KEM Braid ratchet adds post-quantum key updates. Required post-quantum operations fail closed.
- **Chat features.** Multi-device messaging, groups, sealed sender, encrypted attachments, and safety-number verification use the same package.
- **Device-local state.** Storage adapters keep identities, sessions, and message state on the device.
- **Delivery through an adapter.** Operate your own relay or use [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay).

The relay never needs message plaintext or device private keys.

OpenE2EE implements a versioned profile of the published Signal Protocol specifications. It is not affiliated with Signal Messenger and is **not wire-compatible with Signal Messenger or libsignal**. Messages, identities, and safety numbers do not interoperate. See the [notice](./NOTICE) and [documented deviations](./docs/DEVIATIONS.md).

Version `3.0.x`. Public APIs and persisted formats follow semantic versioning.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

Use a current Node LTS release for local development. Each runtime example lists its build requirements.

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

The in-memory store loses identities, sessions, and ratchet state on restart. The in-memory relay has no authentication, authorization, or durable storage. Do not ship either adapter. Continue with the [documentation quickstart](https://docs.open-e2ee.dev/start/quickstart), which explains key custody, relay metadata, prekey replenishment, additional devices, and recovery policy.

## Use your app’s storage and relay

Choose the device-local store for your runtime. Then supply a relay that authenticates each device and implements your product's access policy, or use [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay) as the managed delivery path. The SDK does not require the managed service. [Review Relay plans and exact meter definitions.](https://open-e2ee.dev/relay/pricing)

| Runtime | Storage path | Deployment boundary |
|---|---|---|
| Expo | [`expoStore`](./local/store/expo/README.md) | Configure SQLCipher before schema access. Requires a native development or release build. [Run the Hermes example](./examples/expo/README.md); Expo Go does not include SQLCipher. |
| Browser | [`indexedDbStore`](./local/store/web/README.md) | Use a secure context and a restrictive CSP. Same-origin JavaScript can access stored records and their key. [Browser setup](https://docs.open-e2ee.dev/start/browser). |
| Bare React Native | [`reactNativeStore`](./local/store/react-native/README.md) | Provide an atomic, durable key-value backend and run the exported backend conformance kit. |
| Node | [`nodeStore`](./local/store/node/README.md) | Install `fs-native-extensions@1.2.7` and set an explicit private directory on a trusted local filesystem. |

The [adapter guide](./ADAPTERS.md) defines every storage, relay, vault, and object-store boundary. The [client composition guide](./docs/CLIENT_COMPOSITION.md) shows an Expo client on the OpenE2EE Signal Protocol Relay.

## Security and assurance

The SDK is open source. Our engineering tests remain private. We publish the [testing methodology and dated results](./docs/ASSURANCE.md), including what readers can and cannot verify from this repository. Public CI rebuilds the package, checks types and dependencies, and runs the documented examples.

> Reviewed continuously by adversarial AI agents; not audited by any independent firm.

JavaScript engines do not provide a machine-level constant-time contract or guaranteed zeroization. The [security model](./docs/SECURITY.md) defines the timing, same-process, storage, and metadata boundaries. The [protocol policy](./docs/PROTOCOL_POLICY.md) defines supported modes and fail-closed behavior.

Report a suspected vulnerability privately through the process in [SECURITY](./SECURITY.md). Do not open a public issue for it.

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

Dual-licensed under the [MIT License](./LICENSE-MIT) or the [Apache License 2.0](./LICENSE-APACHE), at your option (`MIT OR Apache-2.0`). See [LICENSE](./LICENSE).

Both licenses provide the software **as is**, without warranties or conditions of any kind. To the extent that applicable law permits, copyright holders and contributors are not liable for damages that arise from its use. Your application must evaluate the SDK against its requirements and secure its deployment, storage, authentication, authorization, and operations. This summary does not modify either license.
