<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/open-e2ee/design/v0.21.2/brand/generated/hosted/open-e2ee-logo-dark.svg">
  <img src="https://raw.githubusercontent.com/open-e2ee/design/v0.21.2/brand/generated/hosted/open-e2ee-logo-light.svg" alt="OpenE2EE" width="340">
</picture>

# OpenE2EE Signal Protocol SDK

**Pure TypeScript for end-to-end encrypted chat.**

Add encrypted messaging to Expo, React Native, browser, and Node applications. The SDK manages device identities, session establishment, and message encryption. Your application supplies storage, user authentication, and a relay for delivery.

The default policy requires post-quantum session establishment and ratcheting. The protocol implementation is open source under the MIT License or the Apache License 2.0, at your option.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-2f6f5e)](./LICENSE)
[![npm version](https://img.shields.io/npm/v/@open-e2ee/signal-protocol-sdk)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2f6f5e)](https://www.npmjs.com/package/@open-e2ee/signal-protocol-sdk#provenance)
[![Checks](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml/badge.svg)](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml)

[Documentation](https://docs.open-e2ee.dev) · [API reference](https://docs.open-e2ee.dev/reference/api) · [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay) · [Security](./SECURITY.md)

## See an encrypted round trip

Press play for device setup, session establishment, encrypted delivery, and decryption on each device.

https://github.com/user-attachments/assets/d8002bc3-c037-41b6-8f48-4008f2d49e6c

The [visual demo](https://open-e2ee.dev/#demo) shows the envelope, ratchets, relay mailbox, and decrypted result. On desktop, type a message and inspect each step. On mobile, a recorded protocol run replays at reading pace. Displayed timings exclude network time.

The demonstrations use real protocol code and cryptography. Application integration requires device-local storage and authenticated delivery.

## What the SDK handles

- **Session establishment and ratcheting.** PQXDH establishes sessions. The ML-KEM Braid ratchet adds post-quantum key updates. Required post-quantum operations fail closed.
- **Chat features.** Multi-device messaging, groups, sealed sender, encrypted attachments, and safety-number verification use the same package.
- **Device-local state.** Storage adapters keep identities, sessions, and message state on the device.
- **Hosted delivery.** Connect to [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay) with the hosted client factory. Advanced integrations can supply a custom transport.

The relay never needs message plaintext or device private keys.

The OpenE2EE Signal Protocol SDK implements a versioned profile of the published Signal Protocol specifications. It is not affiliated with Signal Messenger and is **not wire-compatible with Signal Messenger or libsignal**. Messages, identities, and safety numbers do not interoperate. See the [notice](./NOTICE) and [documented deviations](./docs/DEVIATIONS.md).

Version `9.1.x`. Public APIs and persisted formats follow semantic versioning.

## Install

```bash
npm install @open-e2ee/signal-protocol-sdk
```

Local development needs Node 22.12 or later. The storage guides list platform requirements.

## Connect to the Signal Protocol Relay

Follow the [Sandbox quickstart](https://docs.open-e2ee.dev/relay#sandbox-quickstart).
In the application directory, `oe new` creates the Relay project and its Sandbox
environment. It writes the connection URL to `.env.local` as
`OPEN_E2EE_RELAY_URL`. In a Next.js, Expo, or Vite application, the name has
the public prefix of the framework, for example `EXPO_PUBLIC_OPEN_E2EE_RELAY_URL`.
The URL is public configuration. It is not a credential.

A Sandbox environment uses device-owned identity. `hostedRelaySandboxIdentity`
signs the identity assertion with a key that it keeps in the device-local store.
Use the same store for the client.

This example needs that Sandbox environment. It is not an offline script.

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  createHostedSignalProtocolClient,
  hostedRelaySandboxIdentity,
} from "@open-e2ee/signal-protocol-sdk";

const signal = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    relayUrl: process.env.OPEN_E2EE_RELAY_URL!,
    getIdentityAssertion: hostedRelaySandboxIdentity(storage),
  },
});
```

`hostedRelaySandboxIdentity` works only in a Sandbox environment. In production,
your identity provider signs the assertion: pass a `getIdentityAssertion`
callback that returns a short-lived assertion for the signed-in user. The
[identity guide](https://docs.open-e2ee.dev/relay/identity) describes the
production setup.

Register a handler before you start incoming delivery. Persist each message
before the handler resolves, and use its ID to make repeated writes idempotent.

<!-- doc-snippet:skip requires-external-context -->
```ts
signal.registerHook("onMessageDecrypted", async (message) => {
  await appMessages.accept(message);
});
signal.startRelaySubscription();
await signal.send(recipientUserId, "hello");
```

The hosted factory authenticates and registers the device, then publishes its
public prekeys. `send()` establishes the recipient sessions and sends encrypted
envelopes. The receive handler gets plaintext after device-local decryption.
See [client composition](./docs/CLIENT_COMPOSITION.md) for platform setup.

## Use your app’s storage and relay

Choose the device-local store for your runtime. Then supply a relay that authenticates each device and implements your product's access policy, or use [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay) as the managed delivery path. The SDK does not require the managed service. [Review Relay plans and exact meter definitions.](https://open-e2ee.dev/relay/pricing)

| Runtime | Storage path | Deployment boundary |
|---|---|---|
| Expo | [`expoStore`](./local/store/expo/README.md) | Enable SQLCipher in the expo-sqlite config plugin. The SDK owns the database file, its key, and its migrations. Requires a native development or release build. Expo Go does not include SQLCipher. |
| Browser | [`webSqliteStore`](./local/store/web-sqlite/README.md) | Needs the origin private file system and a CSP that allows `'wasm-unsafe-eval'`. The SDK owns the database file, its key, and its migrations. The key sits in IndexedDB in the same origin, so same-origin JavaScript can read it. Without the origin private file system, the open fails with `OPFS_UNAVAILABLE`. |
| Browser without the origin private file system | [`indexedDbStore`](./local/store/web/README.md) | Use a secure context and a restrictive CSP. Same-origin JavaScript can access stored records and their key. [Browser setup](https://docs.open-e2ee.dev/start/browser). |
| Bare React Native | [`reactNativeStore`](./local/store/react-native/README.md) | Enable SQLCipher with `"op-sqlite": { "sqlcipher": true }` in the app's `package.json`, and install `react-native-keychain`. The SDK owns the database file, its key, and its migrations. Requires a native build; with SQLCipher on, op-sqlite conflicts on iOS with `expo-sqlite`, `expo-updates`, and `use_frameworks!`. |
| Own key-value engine | [`keyValueStore`](./local/store/key-value/README.md) | Provide an atomic, durable key-value backend and a keychain-backed secret vault, and run the exported backend conformance kit. A Realm backend is included. |
| Node and Electron | [`nodeStore`](./local/store/node/README.md) | Install `better-sqlite3-multiple-ciphers` and pass a private directory on a local file system and a secret vault. In Electron, open it in the main process with the safeStorage vault. The SDK owns the database file, its key, and its migrations. |

React Native support starts at React Native 0.83.6 and Expo SDK 55. The peer ranges have no upper bound. Internal CI checks these versions:

| CI check | Versions |
|---|---|
| Add the packed package to a project | React Native 0.83, 0.85, 0.86, and 0.87; Expo SDK 55, 56, and 57 |
| Build the Expo example's Hermes bundle | Expo SDK 55 and 57 |
| Run the Expo example's release build on an Android emulator | Expo SDK 57 with React Native 0.86 |

React Native 0.84 and later use Hermes V1 by default. React Native 0.82 and later run only on the New Architecture.

On React Native and Expo, the SDK reads random bytes only from the global `crypto.getRandomValues`. Install `react-native-get-random-values` 2.x or `react-native-quick-crypto`, and load it before the first SDK call. Without a global source, the SDK throws `SecureRandomUnavailableError`.

The [adapter guide](./ADAPTERS.md) defines every storage, relay, vault, and object-store boundary. The [client composition guide](./docs/CLIENT_COMPOSITION.md) shows an Expo client on the OpenE2EE Signal Protocol Relay.

## Security and assurance

The SDK is open source. Our engineering tests remain private. We publish the [testing methodology and dated results](./docs/ASSURANCE.md), including what readers can and cannot verify from this repository. Public CI rebuilds the client package, checks types and dependencies, and validates the public import surface.

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
