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

- `InMemorySignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/memory`

### Web

- `IndexedDbSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web`

Use this for browser applications. It implements the full core store
contract, including SESAME records, sender-key state, retry message records,
and recovery helpers, and it graduated from experimental by completing every
gate on the checklist below. Deployment still requires the origin-security
review described in the [web adapter guide](./web/README.md).

### Experimental

- `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native` (create it with `await ReactNativeSignalProtocolStore.create({ storage })` and provide your own key-value backend)

This experimental adapter implements the full core store contract, including
SESAME records, sender-key state, retry message records, and recovery helpers.
It remains experimental because its platform hardening and long-run
operational behavior require further deployment evidence.

#### Graduation checklist

The experimental label comes off an adapter when every item below is a named,
continuously running CI gate. Each gate tests the adapter's own contract —
the promises `ISignalProtocolLocalStore` makes — never the platform under it:
browsers, IndexedDB, and React Native are the environment an adapter must
honor its promises in, not the subject of a test.

`IndexedDbSignalProtocolStore` (graduated; the gates keep running):

- [x] Storage contract suites pass in real Chromium, Firefox, and WebKit on
      every change to the source repository. The suites are the same modules
      the jest gate runs, so a matcher means the same thing in both gates.
- [x] Interruption tests: a real tab is destroyed while a write is in
      flight — atomic session/trust commit, identity rotation, fresh-database
      bootstrap, and a prekey batch — and the store reopened from a fresh tab
      is readable on the next `initialize()`, with each atomic security
      commit observed either fully applied or fully absent, never partial.
      Runs in all three engines on every change to the source repository.
- [x] Multi-tab tests: concurrent revision-checked writes from two real
      tabs — two live IndexedDB connections — resolve per the contract's
      compare-and-set promise: one winner per create race, losers told
      instead of silently overwritten, rejected commits leave no partial
      state. Runs in all three engines on every change to the source
      repository.
- [x] Storage-pressure tests: quota exhaustion surfaces as the typed
      `StorageQuotaExceededError` (`STORAGE_QUOTA_EXCEEDED`), never a silent
      partial write. A jest suite drives quota-shaped backend failures
      through every write path in the adapter, and a real Chromium run
      exhausts a clamped origin quota and observes the typed rejection, no
      partial state, and a clean retry once space frees. Runs on every
      change to the source repository.
- [x] Soak evidence: a long-run open/write/close cycle holds memory and
      latency flat. A soak runner drives 2,000 full
      construct/initialize/write/read/close cycles through the adapter in
      one real Chromium page, samples renderer memory - including
      ArrayBuffer backing stores - after forced garbage collection, and
      fails if the late-run median of memory or per-cycle latency grows
      beyond a small tolerance over the early-run median. Runs on every
      change to the source repository, and `npm run soak:web-store` runs
      longer sessions on demand.

`ReactNativeSignalProtocolStore`:

- [ ] Exported backend-conformance kit: the SDK cannot test an
      application-supplied `storage` backend, so it ships the contract suite
      the application runs against its own backend.
- [ ] Reference backend passes that kit on Hermes in CI.
- [ ] Interruption and storage-pressure tests against the reference backend.

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
- [In-memory adapter](./memory/README.md)
