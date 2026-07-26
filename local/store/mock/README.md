# In-Memory Store

`MockSignalProtocolStore` implements `ISignalProtocolLocalStore` in memory for examples, local
development, and deterministic application prototypes.

Real protocol and cryptography; simulated in-memory infrastructure.

## Why it exists

It lets developers exercise client composition without choosing a durable
platform database first. It is intentionally a development adapter, not a
security or persistence boundary.

## Usage

```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const client = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore() },
});
```

All keys, sessions, and trust decisions disappear when the process or adapter
is discarded. Never use this adapter for production accounts.

## Deterministic storage failures

Failure mode is opt-in. A seed and cadence replay the same failing writes, or
you can target the next named store operation:

```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import {
  mockStore,
  MockStorageWriteError,
} from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const storage = mockStore({ failures: { seed: 7 } });
storage.failures.failNextWrite("setMetadata");

try {
  await storage.setMetadata("draft", "encrypted-pointer");
} catch (error) {
  if (error instanceof MockStorageWriteError) {
    // The explicitly injected failure is consumed, so this retry succeeds.
    await storage.setMetadata("draft", "encrypted-pointer");
  }
}
```

Use `writeFailureEvery` for a repeatable cadence. Failure selection uses the
configured seed and operation count, never `Math.random()` or wall-clock time.

See the parent [storage guide](../README.md).
