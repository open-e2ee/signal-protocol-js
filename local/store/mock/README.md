# In-Memory Store

`MockSignalStore` implements `ISignalLocalStore` in memory for examples, local
development, and deterministic application prototypes.

## Why it exists

It lets developers exercise client composition without choosing a durable
platform database first. It is intentionally a development adapter, not a
security or persistence boundary.

## Usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { mockStore } from "@open-e2ee/signal-protocol-sdk/local/store/mock";

const client = await createSignalProtocolClient({
  identity: { userId: "alice" },
  adapters: { storage: mockStore() },
});
```

All keys, sessions, and trust decisions disappear when the process or adapter
is discarded. Never use this adapter for production accounts.

See the parent [storage guide](../README.md).
