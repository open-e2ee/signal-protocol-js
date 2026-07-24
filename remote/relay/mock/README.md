# In-Memory Relay

`MockSignalRelayServer` implements `ISignalRelayServer` in memory for examples
and local application development.

## Why it exists

It provides device registration, public-prekey exchange, and encrypted-envelope
delivery without deploying a backend. It is a development adapter, not an
authorization or durability boundary.

## Usage

```ts
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

See the parent [relay guide](../README.md).
