# Storage Guide

> Infrastructure | Implements `ISignalProtocolLocalStore` | [Architecture](../../ARCHITECTURE.md)

The storage layer owns device-local Signal Protocol state: identity keys,
contact trust, prekeys, sessions, and retry/message-record metadata.

## Why it exists

Protocol state must survive restarts and several security transitions must
commit atomically. `ISignalProtocolLocalStore` makes those requirements explicit
without coupling the client to a database or platform.

## Current Support

### Primary supported adapter

- `ExpoSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/expo`
- Expo integration helpers from `@open-e2ee/signal-protocol-sdk/local/store/expo`, including
  `getKeyStorage`, `getDatabaseKeyManager`, `clearDatabaseKeyCache`, and
  `createPreKeyMaintenanceStore`

### Local development

- `MockSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/mock`

### Experimental

- `IndexedDbSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web`
- `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native` (create it with `await ReactNativeSignalProtocolStore.create({ storage })` and provide your own key-value backend)

These experimental adapters implement the full core store contract, including
SESAME records, sender-key state, retry message records, and recovery helpers.
They remain experimental because their platform hardening and long-run
operational behavior require further deployment evidence.

### Node

- `NodeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/node`

Use this for non-mobile environments that need a filesystem-backed store. It
implements the full core store contract, including SESAME records, sender-key
state, retry message records, and recovery helpers.

## Composition

```ts
import { SignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { ExpoSignalProtocolStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';

// Configure the application-owned Expo/SQLCipher database bindings first.
const signal = await SignalProtocolClient.create(userId, {
  storage: new ExpoSignalProtocolStore(),
});
```

The [Expo guide](./expo/README.md) shows the required database bootstrap.

## Storage Responsibilities

An `ISignalProtocolLocalStore` implementation must preserve:

- account identity key storage
- contact identity trust / TOFU decisions
- prekey lifecycle
- session record persistence
- message record persistence used by retry and resend flows
- local recovery helpers required by the client lifecycle

## Session Record Shape

The current persisted session record shape is version `4`:

```ts
interface SessionRecord {
  currentSession: SessionState | null;
  archivedSessions: Record<string, SessionState>;
  version: 4;
  metadata?: SessionRecordMetadata;
}
```

Older session formats are rejected and reset instead of migrated. Version 4
binds both endpoint composite identities and their explicit identity types into
every live session.

## Atomic Security Commits

Contact trust and session creation/advancement share one atomic commit seam;
responder one-time-prekey consumption joins that same transaction. Separately,
accepted identity rotation and deletion of every bound device session share one
logical transaction. An adapter must never publish only a subset of either
security transition. The shared adapter contract verifies
failure rollback, compare-and-swap behavior, one-time-prekey replay rejection,
and exact per-user session deletion.

For React Native, the supplied backend's `atomicWrite` is a security boundary,
not a batching optimization. It must commit `check`, `set`, `remove`, and
`removeSessionsForUser` operations in one crash-durable transaction. The final
operation must enumerate exact plaintext session metadata inside that same
transaction; prefix matching or enumeration performed before the transaction
can leave a concurrently-created session trusted under a rotated identity.

## Design Notes

- The Expo adapter is the primary supported mobile implementation. Deployment
  still requires review of key custody, backups, and host security.
- `@open-e2ee/signal-protocol-sdk/local/store/expo` is also the package home for Expo-specific
  integration helpers that a real app composes directly.
- Experimental adapters may cover the same contract surface, but should still be positioned carefully until their platform security/performance characteristics are battle-tested.
- Storage adapters should expose the real package contract instead of app-specific wrappers.

## Related Docs

- [README](../../README.md)
- [ADAPTERS](../../ADAPTERS.md)
- [remote/README.md](../../remote/README.md)
- [Expo adapter](./expo/README.md)
- [Node adapter](./node/README.md)
- [Bare React Native adapter](./react-native/README.md)
- [Web adapter](./web/README.md)
- [Mock adapter](./mock/README.md)
