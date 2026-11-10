# Relay

The relay module defines `SignalProtocolRelayServer`, the application-backend contract
for device discovery, public prekeys, encrypted envelopes, key rotation, and
related synchronization.

## Why it exists

Signal Protocol encrypts content between devices, but clients still need an
authenticated service to publish public key material and deliver ciphertext.
The relay boundary keeps that service replaceable without moving private-key or
plaintext ownership to the backend.

## Hosted usage

Use the OpenE2EE Signal Protocol Relay through the hosted client factory:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";

const signalRelayUrl = process.env.OPEN_E2EE_SIGNAL_RELAY_URL ?? process.env.OPEN_E2EE_RELAY_URL!;
const signal = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    relayUrl: signalRelayUrl,
    getIdentityAssertion,
  },
});
```

`oe new` writes the connection URL to `.env.local` as `OPEN_E2EE_SIGNAL_RELAY_URL`,
with the public prefix of the framework in a Next.js, Expo, or Vite
application. An `oe` release before 5.0.0 wrote the earlier name,
`OPEN_E2EE_RELAY_URL`. Read the new name first and the earlier name second.
Supply `storage` for this device and `getIdentityAssertion`. In a Sandbox environment,
pass `hostedSignalProtocolRelaySandboxIdentity(storage)`. In a production project in
device-owned mode, pass `hostedSignalProtocolRelayDeviceOwnedIdentity(storage)`. In a
production project in application-bound mode, pass a callback that returns an
assertion from your backend.

For advanced integrations, implement the `SignalProtocolRelayServer` client
transport against your own backend. That backend must authenticate
mutations, allocate linked-device IDs, consume one-time prekeys atomically,
enforce access policy, and store only encrypted envelopes plus required routing
metadata.

The published package contains client transports and contracts. It does not
include a relay server implementation.

The module entry is `@open-e2ee/signal-protocol-sdk/remote/signal-relay`, and
its types are at `@open-e2ee/signal-protocol-sdk/remote/signal-relay/types`.
The earlier subpaths `@open-e2ee/signal-protocol-sdk/remote/relay` and
`@open-e2ee/signal-protocol-sdk/remote/relay/types` load the same modules. They
are deprecated, and SDK 15.0.0 removes them.

See the [remote guide](../README.md), [interface guide](../../docs/INTERFACES.md),
and [API reference](../../docs/api/README.md).
