# Storage Guide

> Infrastructure | Implements `SignalProtocolLocalStore` | [Architecture](../../ARCHITECTURE.md)

The storage layer owns device-local Signal Protocol state: identity keys,
contact trust, prekeys, sessions, and retry/message-record metadata.

## Why it exists

Protocol state must survive restarts and several security transitions must
commit atomically. `SignalProtocolLocalStore` makes those requirements explicit
without coupling the client to a database or platform.

## Current Support

### Primary supported adapter

- `expoStore` and `ExpoSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/expo`
- `resetExpoStore` and `createPreKeyMaintenanceStore` from the same entry

### Local development

- `InMemorySignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/memory`

### Web

- `webSqliteStore` and `WebSqliteSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web-sqlite`
- `resetWebSqliteStore` and `createPreKeyMaintenanceStore` from the same entry

Use this for browser applications where the origin private file system
works. It keeps the full core store state in an SDK-owned SQLite database in
the origin private file system. SQLite3 Multiple Ciphers encrypts the whole
file in a Wasm worker, and the database key lives in a secret vault, by
default IndexedDB in the same origin. The page's Content Security Policy must
allow `'wasm-unsafe-eval'`. A context without the origin private file system
gets `OPFS_UNAVAILABLE`. The [web SQLite store guide](./web-sqlite/README.md)
covers the policy, the tabs, and the security boundary. It graduated from
experimental by completing every gate on the checklist below.

A Tauri 2 app uses this store in its webview. See the
[Tauri section](./web-sqlite/README.md#tauri).

- `IndexedDbSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/web`

Use this where the origin private file system is not available, and
`webSqliteStore` fails with `OPFS_UNAVAILABLE`. It implements the full core
store contract, including SESAME records, sender-key state, retry message
records, and recovery helpers. It graduated from experimental by completing
every gate on the checklist below. Deployment still requires the
origin-security review described in the [web adapter guide](./web/README.md).

### Bare React Native

- `reactNativeStore` and `ReactNativeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/react-native`
- `resetReactNativeStore` and `createPreKeyMaintenanceStore` from the same entry

Use this for bare React Native applications. It opens an SDK-owned SQLCipher
database on op-sqlite, with its key in the react-native-keychain vault, on the
same SQLite core as the Expo store. It needs the op-sqlite SQLCipher build and
a native build of the app. The [React Native SQLite guide](./react-native/README.md)
covers the setup and the iOS build conflicts.

### Own key-value engine

- `KeyValueSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/key-value` (create it with `await KeyValueSignalProtocolStore.create({ storage, vault })` and provide your own key-value backend and secret vault)
- `createRealmKeyValueBackend` from `@open-e2ee/signal-protocol-sdk/local/store/key-value/realm` (a key-value backend over an open Realm that your application installs)

Use this for applications that supply their own key-value backend, for
example Realm on bare React Native. It implements the full core store
contract, including SESAME records, sender-key state, retry message records,
and recovery helpers. It graduated from experimental by completing every gate
on the checklist below.
The supplied backend is the application's responsibility: verify it with the
exported backend-conformance kit described in the
[key-value store guide](./key-value/README.md).
The value key lives only in the supplied vault. Data without its key is an
error, not a reset. The store reads random bytes from the global
`crypto.getRandomValues`, so a React Native application installs
`react-native-get-random-values` 2.x or `react-native-quick-crypto`.

#### Graduation checklist

The experimental label comes off an adapter when every item below is a named,
continuously running CI gate. Each gate tests the adapter's own contract,
which is the set of promises `SignalProtocolLocalStore` makes. No gate tests
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

`WebSqliteSignalProtocolStore` (graduated, and the gates keep running):

- [x] Storage contract suites pass in real Chromium, Firefox, and WebKit.
      The suites are the same modules the jest gate runs. They run against
      the store on the web driver in a real tab, under a Content Security
      Policy that adds only `'wasm-unsafe-eval'`. Chromium and Firefox run
      on every change to the source repository. Linux WebKit (WebKitGTK) has
      no origin private file system, so the web SQLite store does not run
      there, and the Linux job proves only `OPFS_UNAVAILABLE` in it. A macOS
      WebKit job runs the suites on each change to the web SQLite store, the
      SQLite core, the storage contract, the key vault, the gate, or a
      dependency, not on every change. In each job, a suite that skips for
      want of the origin private file system fails.
- [x] Interruption tests. The gate closes a real tab inside an open
      `BEGIN IMMEDIATE` transaction, the kind of transaction that each store
      commit runs in, while a second tab waits to open the same file. The
      second tab reads the file without the uncommitted writes,
      `PRAGMA integrity_check` returns `ok`, and a new write lands. A crashed
      worker gives `SQLITE_ENGINE_UNAVAILABLE`, and the next open starts a
      new worker. Runs in the three engines on the schedule above.
- [x] Multi-tab tests. Two real tabs share one open file, and each reads
      the other's writes. A read from the second tab waits while the first
      tab holds a write transaction, then sees the committed rows. Two tabs
      that open a new store at the same time write one database key, and
      that key opens the file. A reset gives `INVALID_STATE` while another
      tab has the store open. Runs in the three engines on the schedule
      above.
- [x] Storage-pressure tests. A real Chromium run clamps the origin quota
      and fills the file in the origin private file system until a write
      fails. A single write and an atomic session and trust commit each
      reject with the typed `StorageQuotaExceededError`
      (`STORAGE_QUOTA_EXCEEDED`). The rejected writes leave no partial state:
      no row of the write, no pinned identity, and the one-time prekey stays.
      The store stays open. After the clamp is removed, the same commit
      succeeds, new writes land, and `PRAGMA integrity_check` returns `ok`.
      A first open under a 1 MB and a 4 MB quota rejects with the same typed
      error, and it writes no database key and no database file. After the
      clamp is removed, the open succeeds. A store with two pool files opens,
      reads, and writes under a 3 MB quota that has no room for a new pool.
      Runs in Chromium on the schedule above. The quota clamp is a DevTools
      protocol call, so Firefox and WebKit do not run it.
- [x] Soak evidence: a long run holds latency, memory, and file size flat.
      A soak gate drives the store in real Chromium tabs in three phases:
      150 open/write/read/close cycles in one tab, one session of 2,000
      churn operations over 250 sessions, and 100 writes that two tabs make
      in turn, so that the file moves to the other tab at each write. Each
      write is read back, and `PRAGMA integrity_check` returns `ok` after
      each phase and after each open. A closed store leaves no worker in the
      tab and no lock of the store in the origin. The gate fails if the
      late-run median of latency, of the page heap, or of the worker heap
      grows beyond a small tolerance over the early-run median, if the Wasm
      memory of the worker grows after the first third of the churn, or if
      the database file grows by more than 10% and 64 KiB over the churn.
      Runs in Chromium on each change to the main branch and on each pull
      request that is ready for review. `npm run soak:web-sqlite` also runs
      it in Firefox and WebKit on demand, without the memory checks.

`KeyValueSignalProtocolStore` (graduated, and the gates keep running):

- [x] Exported backend-conformance kit. The SDK cannot test an
      application-supplied `storage` backend. Instead it ships the contract
      suite the application runs against its own backend. The kit exports
      `runBackendConformance` and `assertBackendConformance`, which execute
      sixteen cases against any `KeyValueStorage`:

      - `getItem` returns null for a missing key
      - `setItem` stores, overwrites, and round-trips values
      - `removeItem` deletes a key and tolerates a missing key
      - `getAllKeys` lists exactly the stored keys
      - `removeMany` removes the listed keys and tolerates missing ones
      - `pruneSkippedSenderKeys` uses numeric indexes, exact prefixes, and
        earlier writes in its batch
      - `atomicWrite` applies operations in order
      - `atomicWrite` evaluates checks against the state before the batch
      - `atomicWrite` guards a creation with an `expectedValue` of null
      - a failed check applies none of the batch
      - `removeSessionsForUser` removes only exact userId matches under the
        prefix
      - `removeSessionsForUser` sees earlier writes in its batch
      - `removeSenderKeyHandoffs` removes only keys whose segments match
        under the prefix
      - `removeSenderKeyHandoffs` sees earlier writes in its batch
      - concurrent guarded batches have exactly one winner
      - committed writes survive a reopen

      A jest gate proves the kit catches a non-atomic backend, a
      prefix-matching session removal, and an unserialized backend, on every
      change to the source repository.
- [x] Reference backend passes that kit on Hermes in CI. The source
      repository holds an in-memory reference backend, which specifies the
      backend contract in executable form. It is not part of the package. On
      each source-repository change, a named gate bundles the kit and runs it
      on the reference backend. That gate uses the Hermes V1 CLI that React
      Native 0.86 uses, with only the globals of a bare React Native app. The
      runner requires an explicit pass line for each case because Hermes
      exits 0 on an unhandled async rejection.
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

- `nodeStore` and `NodeSignalProtocolStore` from `@open-e2ee/signal-protocol-sdk/local/store/node`

Use this for Node and the Electron main process. `await nodeStore({ directory,
vault })` opens an SDK-owned SQLCipher database on the
`better-sqlite3-multiple-ciphers` peer, with its key in the vault that the app
passes. The [Node guide](./node/README.md) covers the owner lock, a lost key,
and reset.

## Composition

<!-- doc-snippet:skip requires-external-context -->
```ts
import { DefaultSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';

const signal = await DefaultSignalProtocolClient.create(userId, {
  storage: await expoStore(),
});
```

The [Expo guide](./expo/README.md) covers the native build and the database key.
The [React Native SQLite guide](./react-native/README.md) covers the same for
bare React Native.

## Conformance kit for a custom store

- `runLocalStoreConformance` and `assertLocalStoreConformance` from `@open-e2ee/signal-protocol-sdk/local/store/conformance`

An application that implements `SignalProtocolLocalStore` itself runs this
kit against its store. The kit has no framework or platform dependencies. It
runs unchanged under jest, Node, a browser, or Hermes, and it loads no
optional peer. The kit gets a fresh, empty store from `createStore` for each
case. The other options are hooks for the cases that need them:

- `reopen` closes the store and opens the same data again. The two reopen
  cases skip without it.
- `armWriteFailure` makes the next atomic commit fail after its first write.
  Each atomic commit that the kit arms holds a receive record, so a failure
  on that write works when the store writes it after another record. The
  two rollback cases skip without it.
- `readRawBytes` returns the bytes that the store keeps. The ciphertext case
  skips without it.
- `closeStore` releases a store after its case.

The kit has these cases:

- identity overwrite: a key pair and its registration ID for `'aci'` and
  `'pni'`, and an overwrite of each with a new registration ID. The write of
  one type does not change the other type.
- identity overwrite after reopen
- session trust commit: a commit of a session, its contact identity, and its
  receive record, and a refused commit that writes nothing
- session trust commit rollback
- sender key receive commit: a sender key record with its receive record,
  the consumed skipped key, and skipped key eviction
- sender key receive commit rollback
- metadata compare-and-set: a match, a mismatch, an absent value, and one
  winner among concurrent calls
- receive record insert and compare-and-set
- receive record listing: arrival order, then work ID order, an exclusive
  `after` cursor, the default page size, and the filters
- receive record completion and usage
- durability after reopen: each kind of write survives a reopen
- no plaintext at rest: the stored bytes hold no known plaintext. It runs
  only when the store declares a cipher.
- protection declaration: `store.protection` is a valid declaration

`runLocalStoreConformance` reports each case as passed, skipped, or failed,
and it does not throw. A skipped case is a name with no reason. The result
also carries the `protection` declaration of the store, or null when the
declaration case fails. `assertLocalStoreConformance` throws with every
problem listed. A failed case is a problem. A skipped rollback case is also a
problem, because a store must prove that its atomic commits roll back. Use
the assert form in the automated checks of the application.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { assertLocalStoreConformance } from '@open-e2ee/signal-protocol-sdk/local/store/conformance';

await assertLocalStoreConformance({
  createStore: () => openMyStore({ name: freshName() }),
  reopen: (store) => reopenMyStore(store),
  armWriteFailure: (store) => failNextReceiveRecordWrite(store),
  readRawBytes: (store) => readMyStoreFiles(store),
  closeStore: (store) => closeMyStore(store),
});
```

The kit does not cover `SenderKeyHandoffStore`, `MessageRecordStore`, or
`SendLogStore`. A store that implements those interfaces needs its own
checks for them. On every change to the source repository, each shipped
store runs the kit under jest. The key-value store and the React Native
SQLite store also run it under Hermes. The web stores also run it in a real
browser.

## Storage Responsibilities

An `SignalProtocolLocalStore` implementation must preserve:

- account identity key storage
- contact identity trust / TOFU decisions
- prekey lifecycle
- session record persistence
- message record persistence used by retry and resend flows
- local recovery helpers required by the client lifecycle
- a `protection` declaration that states what the store does: its
  encryption at rest and the custody of its key. Client creation fails
  without one, and [Content Recovery](../../docs/PROTOCOL_POLICY.md#content-recovery)
  reads it

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

Contact trust and session creation/advancement share one atomic commit boundary.
Responder one-time-prekey consumption joins that same transaction. Separately,
one logical transaction accepts an identity rotation and deletes every bound
device session. An adapter must never publish only a subset of either
security transition. The shared adapter contract verifies
failure rollback, compare-and-swap behavior, one-time-prekey replay rejection,
and exact per-user session deletion.

For the key-value store, the supplied backend's `atomicWrite` is a security boundary.
It must commit `check`, `set`, `remove`, `removeSessionsForUser`,
`pruneSkippedSenderKeys`, and `removeSenderKeyHandoffs` operations in one
crash-durable transaction.
The `removeSessionsForUser` operation must enumerate exact plaintext session
metadata inside that transaction. An adapter that matches a prefix or enumerates before the
transaction can leave a concurrently-created session trusted under a rotated
identity.

The `pruneSkippedSenderKeys` operation enumerates keys under its exact `keyPrefix`
inside the transaction. It removes the lowest numeric chain indexes until
`maxCount` keys remain. The chain index is the last colon-separated key component.
The operation observes earlier writes in the same batch. Equal indexes belong
to distinct generations and remain separate entries.

The `removeSenderKeyHandoffs` operation enumerates keys under its exact
`keyPrefix` inside the transaction. The part of a key after the prefix has five
colon-separated segments: the group hash, the generation, the account hash, the
recipient hash, and the entry hash. The operation removes every key whose group,
account, and recipient segments equal each hash that it gives. A hash that it
omits matches every value. A key of another shape stays. The operation observes
earlier writes in the same batch, and `assertBackendConformance` checks that
rule.

For eviction ties, the store may remove either generation.
Use `createTransactionalKeyValueBackend` to apply
these operations through the shared interpreter, and verify custom backends
with `assertBackendConformance`.

## Design Notes

Reviewed: 2026-10-20.

Receive records use the same encryption and transaction boundary as protocol state.

The `commitSessionTrust` method commits the receive record, ratchet state, contact trust, and consumed prekeys together.
The `storeSenderKeyRecord` method commits the full sender-key record and every
`SenderKeyReceiveCommit` effect together. These effects include skipped-key
additions, capacity eviction, skipped-key consumption, and an optional receive
record. The manager stages additions until authentication and decryption
succeed.

The store applies additions in order, with capacity eviction before
each addition. A rejected commit preserves the prior record, skipped keys,
and receive records. This applies to current and archived generations and
to receives without a durable ID. A retry uses that preserved state.

An adapter must reject the complete transaction if any write fails.
When the database file of a SQLite store cannot grow because the disk or the
storage quota is full, the write rejects with `StorageQuotaExceededError`
(`STORAGE_QUOTA_EXCEEDED`). SQLite rolls the write back, and the store stays
open. Free space, then retry the write.

A receive record keeps one decrypted message until the client completes it.
`commitSessionTrust` with `receiveWork` and `storeSenderKeyRecord` with `work`
write the record in the same transaction as the ratchet state. Generic
metadata cannot hold this record, because a metadata write does not join the
ratchet transaction. Five methods own the records:

- `getReceiveWork(workId)` reads one record.
- `putReceiveWork(record, expectedRevision)` inserts the record when
  `expectedRevision` is `null`. Otherwise it replaces the record that has
  that revision. On a mismatch it returns `false` and writes nothing.
- `listReceiveWork(query)` lists the records in ascending `(arrivalSeq,
  workId)` order, and compares `workId` values by UTF-16 code unit. It
  filters by `stage`, `dueBy`, and the `after` cursor, and returns at most
  `limit` records (100 when not set). A record passes the cursor when its
  `arrivalSeq` is above the cursor `arrivalSeq`, or equal to it with a
  `workId` above the cursor `workId`.
- `receiveWorkUsage({ groupId })` counts the records and their bytes. With a
  `groupId`, it counts only the records that wait for an update of that group.
- `completeReceiveWork(workId, expectedRevision, metadata)` deletes the record
  and applies the metadata writes in one atomic write. On a revision mismatch
  it returns `false` and writes nothing.

Each store keeps the arrival order, the stage, the due time, and the size in
clear index fields beside the record, so a listing or a usage count does not
decrypt each record. Expo, bare React Native, and Node use SQLCipher, and the
web SQLite store encrypts its whole file with SQLite3 Multiple Ciphers. The
IndexedDB web store and the key-value store encrypt each record with their
existing store key. For a record that waits for its group, they keep a keyed
hash of the group ID, not the group ID. A SQLite store with
`encryptionAtRest: false` and the in-memory store keep the records without
encryption.

At the first open after an upgrade from an earlier SDK, each durable store
converts the legacy received-content rows to receive records, and writes the
conversion marker last. An interrupted conversion continues at the next open,
and skips each row that already has a record. A row that does not parse stays
under its legacy key. The store logs the key, never the value, and keeps the
key in the marker.

The IndexedDB web store and the key-value store also encrypt each metadata
value with their store key. Their metadata key names stay in clear text. Some
names hold a group ID, a recipient user ID, or a message ID. These stores
encrypt clear metadata values from an earlier SDK when they open, and they
write the migration marker last.
An earlier SDK cannot read the encrypted values. An encrypted SQLite store
keeps the metadata keys and values inside its file cipher.

`protocol.contentRecovery` does not decide whether a store keeps receive
records. That policy covers only the content that a sender keeps to answer
a retry request. Every store keeps receive records, also a store whose
`protection` is `none`.

The SDK removes content after durable handling and retains separate bounded
duplicate evidence. The receive queue deletes a receive record whose content
waited 30 days, after `onReceiveExpired` runs. A deletion does not erase the
bytes. See the [security model](../../docs/SECURITY.md#storage-boundary).
The host application must use idempotent writes keyed by message ID.

- The Expo adapter is the primary supported mobile implementation. Deployment
  still requires review of key custody, backups, and host security.
- `@open-e2ee/signal-protocol-sdk/local/store/expo` is also the package home for Expo-specific
  integration helpers that a real app composes directly.
- `@open-e2ee/signal-protocol-sdk/local/store/react-native` is the same SQLite
  store for bare React Native, on op-sqlite and the react-native-keychain vault.
- An adapter carries the experimental label until every item on its
  graduation checklist is a named, continuously running CI gate. The web
  SQLite store, the IndexedDB web adapter, and the key-value adapter completed
  theirs.
- Storage adapters should expose the real package contract instead of app-specific wrappers.

## Related Docs

- [README](../../README.md)
- [ADAPTERS](../../ADAPTERS.md)
- [remote/README.md](../../remote/README.md)
- [Expo adapter](./expo/README.md)
- [Node adapter](./node/README.md)
- [Web SQLite store](./web-sqlite/README.md)
- [React Native SQLite store](./react-native/README.md)
- [Key-value store](./key-value/README.md)
- [Web adapter](./web/README.md)
- [In-memory adapter](./memory/README.md)
