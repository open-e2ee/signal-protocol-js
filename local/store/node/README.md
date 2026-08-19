# Node Store

`NodeSignalProtocolStore` provides Node.js protocol storage using encrypted,
crash-durable filesystem state.

It implements all of `ISignalProtocolLocalStore`. That covers identity,
prekeys, sessions, Kyber prekeys, Sesame device records, sender keys, and
message records. Multi-device and group flows therefore work in Node without a
custom adapter.

The class declares `implements ISignalProtocolLocalStore`, so the compiler
rejects any build that omits a member or changes its signature. That check is
the guarantee behind this paragraph, not a manual audit.

## Why it exists

Servers, command-line tools, and desktop processes may need persistent protocol
state without browser or mobile dependencies. The Node adapter supplies that
boundary while allowing each deployment to choose an explicit data directory.

## Usage

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { nodeStore } from "@open-e2ee/signal-protocol-sdk/local/store/node";

const storage = await nodeStore({
  dataDir: "/var/lib/my-app/signal-protocol",
});

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

Use a private directory on a trusted local filesystem. The adapter encrypts
records and restricts file permissions, but the application still owns OS
account isolation, backups, volume security, process access, and secure account
reset. Do not place the store on an eventually consistent or multi-writer
network filesystem.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
