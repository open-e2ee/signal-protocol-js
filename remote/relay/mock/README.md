# In-Memory Relay

`MockSignalRelayServer` implements `ISignalRelayServer` in memory for examples
and local application development.

Real protocol and cryptography; simulated in-memory infrastructure.

## Why it exists

It provides device registration, public-prekey exchange, and encrypted-envelope
delivery without deploying a backend. It is a development adapter, not an
authorization or durability boundary.

## Usage

```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";

const relay = mockRelay();
const client = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore(), relay },
});

await client.syncToServer();
```

All registered devices, public keys, mailboxes, and provisioning state disappear
with the adapter. It performs no real account authentication, rate limiting,
abuse prevention, or durable delivery and must not be used in production.

## Deterministic failure and recovery exercises

Failure mode is opt-in and seeded. The default `mockRelay()` remains the
deterministic happy path:

```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { mockRelay } from "@open-e2ee/signal-protocol-sdk/remote/relay/mock";

const relay = mockRelay({
  failures: {
    seed: 7,
    latencyMs: 20,
    duplicateDeliveryEvery: 3,
    reorderDeliveryPairs: true,
    rejectAuthorization: true,
    exhaustOneTimePreKeys: true,
  },
});

relay.failures.disconnect("bob", 1);
// Sends remain in Bob's encrypted mailbox.
relay.failures.reconnect("bob", 1);
```

`flushReordered()` releases an unmatched final envelope. `configure()` changes
a scenario without rebuilding clients. Authorization rejection raises
`SealedSenderAuthError`, allowing the client's documented identified-delivery
fallback. One-time-prekey exhaustion withholds both EC and KEM one-time keys but
keeps the KEM last-resort key, so strict-PQ examples exercise the intended
post-quantum recovery path rather than a silent classical downgrade. Failure
selection uses the configured seed and delivery count, never `Math.random()` or
wall-clock time.

See the parent [relay guide](../README.md).
