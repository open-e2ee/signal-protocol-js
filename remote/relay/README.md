# Relay

The relay module defines `SignalProtocolRelayServer`, the application-backend contract
for device discovery, public prekeys, encrypted envelopes, key rotation,
provisioning, and related synchronization.

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

const signal = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    relayUrl,
    getIdentityAssertion,
  },
});
```

Get `relayUrl` from the OpenE2EE console. Supply `storage` for this device and
`getIdentityAssertion` for the configured identity provider.

For advanced integrations, implement the `SignalProtocolRelayServer` client
transport against your own backend. That backend must authenticate
mutations, allocate linked-device IDs, consume one-time prekeys atomically,
enforce access policy, and store only encrypted envelopes plus required routing
metadata.

The published package contains client transports and contracts. It does not
include a relay server implementation.

See the [remote guide](../README.md), [interface guide](../../docs/INTERFACES.md),
and [API reference](../../docs/api/README.md).
