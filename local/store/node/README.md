# Node Store

`NodeSignalProtocolStore` provides Node.js protocol storage using encrypted,
crash-durable filesystem state.

It implements all of `SignalProtocolLocalStore`. That covers identity,
prekeys, sessions, Kyber prekeys, Sesame device records, sender keys, and
message records. Multi-device and group flows therefore work in Node without a
custom adapter.

The class declares `implements SignalProtocolLocalStore`, so the compiler
rejects any build that omits a member or changes its signature. That check is
the guarantee behind this paragraph, not a manual audit.

## Why it exists

Servers, command-line tools, and desktop processes may need persistent protocol
state without browser or mobile dependencies. The Node adapter supplies that
boundary while allowing each deployment to choose an explicit data directory.

## Usage

Install the Node adapter's native file-lock dependency:

```sh
npm install fs-native-extensions@1.2.7
```

The exact version passes the supported-runtime checks on Node.js 22 and 26.
Dependency upgrades must pass the supported-runtime checks. Other adapters do not load this dependency.
If the native module or file locking is unavailable, the Node store refuses to open.

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

## Concurrent access and reset

A kernel file lock serializes security-state transactions across processes and
independent handles. Directory aliases use the same lock inode.
The lock covers the key check, state read, conditional mutation, and durable write.
It does not make several SDK calls one transaction.

A contender stops after 30 seconds without acquiring the lock. It does not
remove the lock or continue without exclusion. Process termination releases
the kernel lock. The next initialization removes interrupted temporary writes.

Reset removes stored data but retains the empty `.database.lock` file and its
directory. It preserves unrelated files. Do not remove the lock file while a process can use the store.
An interrupted reset blocks access until an explicit reset finishes.
Handles with the old database key refuse subsequent writes after reset.

The application owns a coordinated key rotation across all encrypted records.
Changing only the key file is not a complete rotation.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
