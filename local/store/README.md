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
and recovery helpers. It graduated from experimental by completing every
gate on the checklist below. Deployment still requires the origin-security
review described in the [web adapter guide](./web/README.md).

### Bare React Native

- `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native` (create it with `await ReactNativeSignalProtocolStore.create({ storage })` and provide your own key-value backend)

Use this for bare React Native applications that supply their own key-value
backend. It implements the full core store contract, including SESAME records,
sender-key state, retry message records, and recovery helpers. It graduated
from experimental by completing every gate on the checklist below.
The supplied backend is the application's responsibility: verify it with the
exported backend-conformance kit described in the
[React Native adapter guide](./react-native/README.md).

#### Graduation checklist

The experimental label comes off an adapter when every item below is a named,
continuously running CI gate. Each gate tests the adapter's own contract,
which is the set of promises `ISignalProtocolLocalStore` makes. No gate tests
the platform under it. Browsers, IndexedDB, and React Native are the
environment an adapter must honor its promises in, not the subject of a test.

`IndexedDbSignalProtocolStore` (graduated, and the gates keep running):

- [x] Storage contract suites pass in real Chromium, Firefox, and WebKit on
      every change to the source repository. The suites are the same modules
      the jest gate runs, so a matcher means the same thing in both gates.
- [x] Interruption tests. The gate destroys a real tab mid-write, then
      reopens the store from a fresh tab. The interrupted writes are an
      atomic session/trust commit, an identity rotation, a fresh-database
      bootstrap, and a prekey batch. The reopened store is readable on the
      next `initialize()`. The store shows each atomic security commit as
      fully applied or fully absent, never partial. Runs in all three
      engines on every change to the source repository.
- [x] Multi-tab tests. Concurrent revision-checked writes from two real
      tabs, over two live IndexedDB connections, resolve per the contract's
      compare-and-set promise. That promise gives one winner per create
      race. It tells the losers instead of silently overwriting them. A
      rejected commit leaves no partial state. Runs in all three engines on
      every change to the source repository.
- [x] Storage-pressure tests: quota exhaustion surfaces as the typed
      `StorageQuotaExceededError` (`STORAGE_QUOTA_EXCEEDED`), never a silent
      partial write. A jest suite drives quota-shaped backend failures
      through every write path in the adapter. A real Chromium run exhausts
      a clamped origin quota. That run observes the typed rejection, no
      partial state, and a clean retry once space frees. Runs on every
      change to the source repository.
- [x] Soak evidence: a long-run open/write/close cycle holds memory and
      latency flat. A soak runner drives 2,000 full
      construct/initialize/write/read/close cycles through the adapter in
      one real Chromium page. It samples renderer memory, including
      ArrayBuffer backing stores, after forced garbage collection. It fails
      if the late-run median of memory or per-cycle latency grows beyond a
      small tolerance over the early-run median. Runs on every change to the
      source repository, and `npm run soak:web-store` runs longer sessions
      on demand.

`ReactNativeSignalProtocolStore` (graduated, and the gates keep running):

- [x] Exported backend-conformance kit. The SDK cannot test an
      application-supplied `storage` backend. Instead it ships the contract
      suite the application runs against its own backend. The kit exports
      `runBackendConformance` and `assertBackendConformance`, which execute
      thirteen cases against any `ReactNativeKeyValueStorage`:

      - round-trips
      - key listing
      - batch removal
      - in-order atomic application
      - checks evaluated against pre-batch state
      - null-guarded creation
      - all-or-nothing failure
      - exact-userId session removal with in-batch visibility
      - one winner between concurrent guarded batches
      - durability across reopen

      A jest gate proves the kit catches a non-atomic backend, a
      prefix-matching session removal, and an unserialized backend, on every
      change to the source repository.
- [x] Reference backend passes that kit on Hermes in CI. The SDK ships
      `createReferenceReactNativeBackend`, which specifies the backend
      contract in executable form. A named gate bundles the kit with esbuild
      and runs it against the reference backend. That gate uses the
      sha256-pinned Hermes CLI, the engine React Native ships with. It runs
      on every change to the source repository. The runner requires an
      explicit pass sentinel because Hermes exits 0 on an unhandled async
      rejection.
- [x] Interruption tests against the reference backend. A simulated process
      kill before commit leaves each atomic security write fully absent
      after reopen. Those writes are a session/trust commit, an identity
      rotation, and a trust verification. An identical retry then lands the
      write fully applied. Runs on every change to the source repository.
- [x] Storage-pressure tests against the reference backend. Quota
      exhaustion surfaces as the typed `StorageQuotaExceededError`
      (`STORAGE_QUOTA_EXCEEDED`), never a silent partial write. A jest suite
      drives quota-shaped backend failures through every write path. A
      real-quota run observes the typed rejection, no partial state, and a
      clean retry once space frees. Runs on every change to the source
      repository.

### Node

- `NodeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/node`

Use this for non-mobile environments that need a filesystem-backed store. It
implements the full core store contract, including SESAME records, sender-key
state, retry message records, and recovery helpers.

## Composition

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
```ts
interface SessionRecord {
  currentSession: SessionState | null;
  archivedSessions: Record<string, SessionState>;
  version: 4;
  metadata?: SessionRecordMetadata;
}
```

The SDK rejects and resets older session formats instead of migrating them.
Version 4
binds both endpoint composite identities and their explicit identity types into
every live session.

## Atomic Security Commits

Contact trust and session creation/advancement share one atomic commit seam.
Responder one-time-prekey consumption joins that same transaction. Separately,
one logical transaction accepts an identity rotation and deletes every bound
device session. An adapter must never publish only a subset of either
security transition. The shared adapter contract verifies
failure rollback, compare-and-swap behavior, one-time-prekey replay rejection,
and exact per-user session deletion.

For React Native, the supplied backend's `atomicWrite` is a security boundary,
not a batching optimization. It must commit `check`, `set`, `remove`, and
`removeSessionsForUser` operations in one crash-durable transaction. The final
operation must enumerate exact plaintext session metadata inside that same
transaction. An adapter that matches a prefix or enumerates before the
transaction can leave a concurrently-created session trusted under a rotated
identity.

## Design Notes

- The Expo adapter is the primary supported mobile implementation. Deployment
  still requires review of key custody, backups, and host security.
- `@open-e2ee/signal-protocol-sdk/local/store/expo` is also the package home for Expo-specific
  integration helpers that a real app composes directly.
- An adapter carries the experimental label until every item on its
  graduation checklist is a named, continuously running CI gate. Both the web
  and bare React Native adapters completed theirs.
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
