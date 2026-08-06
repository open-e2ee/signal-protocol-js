# Relay

The relay module defines `ISignalProtocolRelayServer`, the application-backend contract
for device discovery, public prekeys, encrypted envelopes, key rotation,
provisioning, and related synchronization.

## Why it exists

Signal Protocol encrypts content between devices, but clients still need an
authenticated service to publish public key material and deliver ciphertext.
The relay boundary keeps that service replaceable without moving private-key or
plaintext ownership to the backend.

## Local usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { inMemoryStore } from "@open-e2ee/signal-protocol-sdk/local/store/memory";
import { inMemoryRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/memory";

const relay = inMemoryRelay();

const client = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: inMemoryStore(), relay },
});

await client.syncToServer();
```

For production, implement `ISignalProtocolRelayServer` or use the
[Convex adapter](./convex/README.md). The application backend must authenticate
mutations, allocate linked-device IDs, consume one-time prekeys atomically,
enforce access policy, and store only encrypted envelopes plus required routing
metadata.

See the [remote guide](../README.md), [interface guide](../../docs/INTERFACES.md),
[in-memory relay guide](./memory/README.md), and [API reference](../../docs/api/README.md).
