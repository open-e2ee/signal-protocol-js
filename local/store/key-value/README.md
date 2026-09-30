# Key-Value Store

`KeyValueSignalProtocolStore` implements `SignalProtocolLocalStore` over an
application-provided persistent key-value backend. It is for applications that
choose their own storage engine. A bare React Native application that lets the
SDK own the database uses the [React Native SQLite store](../react-native/README.md).

## Why it exists

Applications that choose their own storage engine choose different engines. The
store keeps that choice outside the SDK while requiring the atomic operations
needed for trust, session, and one-time-prekey transitions. The SDK ships one
backend, for Realm. For another engine, you give
`createTransactionalKeyValueBackend` the engine's transaction, and you verify
the result with the conformance kit.

## Requirements

The store gets random bytes from the global `crypto.getRandomValues`. Install
`react-native-get-random-values` 2.x or `react-native-quick-crypto`, and load
it at app startup before the first SDK call. Without a global source, the SDK
throws `SecureRandomUnavailableError`. The store needs no `crypto.subtle`
polyfill. AES-256-GCM uses Web Crypto when `crypto.subtle` exists and the
bundled Noble implementation otherwise. The [README](../../../README.md#use-your-apps-storage-and-relay)
lists the supported React Native versions.

The store also needs a `SignalProtocolLocalSecretVault` backed by the platform
keychain or keystore. On bare React Native, use
`ReactNativeKeychainSignalProtocolSecretVault` from
`@open-e2ee/signal-protocol-sdk/local/vault/react-native-keychain`. The
[secret-vault guide](../../vault/README.md) describes the interface and the
adapters. Without a vault, `create`, `reset`, and `keyValueStore` throw an
`EncryptionError` with code `SECRET_VAULT_REQUIRED`.

## Usage

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  keyValueStore,
  type KeyValueStorage,
} from "@open-e2ee/signal-protocol-sdk/local/store/key-value";

const keyValueStorage: KeyValueStorage = appProtocolStorage;
const storage = await keyValueStore({ storage: keyValueStorage, vault });

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

The injected backend's `atomicWrite()` is a security boundary. It must evaluate
compare-and-swap checks and commit all writes, removals, and exact per-user
session deletion atomically and durably, including across process termination.
Independent writes committed one after another are not sufficient.

## Key custody

The store encrypts each record with a 32-byte value key. The store makes the
key from secure random bytes on the first open and keeps it only in the vault,
under the name `signal_key_value_encryption_key`. The key never goes into the
key-value backend.

A backend that holds store data while the vault holds no key is a lost key.
`create` then rejects with an `EncryptionError` whose code is
`LOCAL_STORE_KEY_LOST`, and it changes nothing. The store does not replace the
key, because a new key cannot read the old data. Restore the vault entry, or
reset the store:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { EncryptionError, EncryptionErrorCode } from "@open-e2ee/signal-protocol-sdk";
import { KeyValueSignalProtocolStore } from "@open-e2ee/signal-protocol-sdk/local/store/key-value";

try {
  store = await KeyValueSignalProtocolStore.create({ storage: keyValueStorage, vault });
} catch (error) {
  if (!(error instanceof EncryptionError) || error.code !== EncryptionErrorCode.LOCAL_STORE_KEY_LOST) {
    throw error;
  }
  // Deletes every store record, then makes a new key. The device then needs a new identity.
  store = await KeyValueSignalProtocolStore.reset({ storage: keyValueStorage, vault });
}
```

`reset` deletes the store's records in one `atomicWrite`, and then writes a new
key to the vault. It leaves backend entries outside the store's `@signal:`
prefix. `clearAllKeys()` uses the same two steps on an open store. If the
process stops between the two steps, the backend holds no store data and the
vault holds the old key or none, so the next `create` opens an empty store.

## Realm

The subpath `@open-e2ee/signal-protocol-sdk/local/store/key-value/realm`
contains a backend for [Realm](https://github.com/realm/realm-js). The SDK does
not import `realm` and does not declare it as a dependency or peer. The
adapter takes any object shaped like an open Realm. Your application installs
`realm` and opens the Realm with the store's object schema:

<!-- doc-snippet:skip requires-external-context -->
```ts
import Realm from "realm";
import { KeyValueSignalProtocolStore } from "@open-e2ee/signal-protocol-sdk/local/store/key-value";
import {
  createRealmKeyValueBackend,
  realmKeyValueSchema,
} from "@open-e2ee/signal-protocol-sdk/local/store/key-value/realm";

const realm = await Realm.open({
  path: "signal-protocol.realm",
  schema: [realmKeyValueSchema],
});
const store = await KeyValueSignalProtocolStore.create({
  storage: createRealmKeyValueBackend(realm),
  vault,
});
```

Each store write runs in one `realm.write` transaction. Realm commits the
transaction when the callback returns and cancels it when the callback throws,
so a failed check or a failed write commits nothing. The store runs each call
after the calls before it. If your application holds a Realm write transaction
open when a store write runs, for example after `realm.beginTransaction()`, the
write rejects with `INVALID_STATE`, because the store cannot control a
transaction that it did not open. A write that Realm rejects, for example on a
full disk, rejects with Realm's own error.

The schema name `SignalProtocolKeyValue` and its fields are stored in your
Realm file. If you already use a Realm, add `realmKeyValueSchema` to its schema
list, or open a separate Realm file for the store.

The adapter is tested with the conformance kit on realm 20.2.0 in Node,
including a reopen of the same Realm file. Manual checks ran the kit in
React Native apps in the iOS 26.2 simulator and in an Android emulator. All
13 cases passed in each. The SDK does not test the adapter
on a physical device. Run the conformance kit on your target devices with
your Realm build before you ship.

### Realm maintenance status

Realm has no maintainer. Examine these facts before you choose it:

- MongoDB ended Realm on 2025-09-30.
- The last release of `realm` is 20.2.0, from 2025-08-11.
- The build fails with Xcode 26.4
  ([realm-js#7115](https://github.com/realm/realm-js/issues/7115)). The issue
  was closed with no fix.
- The Android native libraries are not aligned for 16 KB pages
  ([realm-js#7129](https://github.com/realm/realm-js/issues/7129)). Google Play
  requires 16 KB page support from 2027-02-01.

Realm's native build is part of your application, so these limits apply to your
build and not to the SDK.

### Limits

- Key names are plaintext. The store encrypts each value, but the key of a
  record can contain protocol identifiers, for example a user ID and a device
  ID.
- The backend contract has no prefix query. The store finds records by a
  prefix, for example a user's sessions, and it checks for data on open. Each
  of these operations calls `getAllKeys()`, which reads every key in the
  backend. Their time increases with the total number of records.

## Another storage engine

For an engine with transactions, do not write the `atomicWrite` rules again.
`createTransactionalKeyValueBackend` owns them, and the Realm backend uses the
same function. Give it two calls:

- `transaction(body)` opens one write transaction, calls `body` once with a
  `KeyValueTransaction` handle over it, and commits when `body` returns. When
  `body` throws, it rolls back and rethrows. It returns, or resolves, after the
  commit is durable.
- `read(body)` calls `body` with a handle over committed data and returns the
  result.

The handle has four synchronous calls: `get`, `set`, `delete`, and
`keysWithPrefix`, which compares case-sensitively. The handle is synchronous
because Realm's `write` commits when its synchronous callback returns, so a
batch that awaits cannot run inside it. An engine with an asynchronous
transaction runs the synchronous body inside it. This sketch does that with
[op-sqlite](https://github.com/OP-Engineering/op-sqlite), whose `executeSync`
runs on the connection that holds the transaction:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { open } from "@op-engineering/op-sqlite";
import {
  createTransactionalKeyValueBackend,
  KeyValueSignalProtocolStore,
  type KeyValueTransaction,
} from "@open-e2ee/signal-protocol-sdk/local/store/key-value";

const db = open({ name: "signal-protocol.sqlite" });
db.executeSync(
  "CREATE TABLE IF NOT EXISTS signal_key_value (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
);

const handle: KeyValueTransaction = {
  get(key) {
    const row = db.executeSync("SELECT value FROM signal_key_value WHERE key = ?", [key]).rows[0];
    return row ? String(row.value) : null;
  },
  set(key, value) {
    db.executeSync(
      "INSERT INTO signal_key_value (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      [key, value]
    );
  },
  delete(key) {
    db.executeSync("DELETE FROM signal_key_value WHERE key = ?", [key]);
  },
  keysWithPrefix(prefix) {
    return db
      .executeSync("SELECT key FROM signal_key_value WHERE substr(key, 1, ?) = ?", [prefix.length, prefix])
      .rows.map((row) => String(row.key));
  },
};

const store = await KeyValueSignalProtocolStore.create({
  storage: createTransactionalKeyValueBackend({
    transaction: (body) => db.transaction(async () => body(handle)),
    read: (body) => body(handle),
  }),
  vault,
});
```

The backend runs each call after the calls before it, so its own reads and
writes do not overlap. It cannot order your application's statements. Give the
store a database that only the store uses, so that no other transaction is
open on the connection when the store reads or writes. The SDK does not run
this sketch. Run the conformance kit over your backend on your target devices.

When the engine returns without calling `body`, or calls it twice, the write
rejects with `INVALID_STATE`. To signal a full disk, throw an error whose
`name` is `'QuotaExceededError'` before the commit. The store maps it to
`StorageQuotaExceededError`.

## Verifying your backend

The store's guarantees hold only over a backend that honors the
`KeyValueStorage` contract, and the SDK cannot test the backend
your application supplies. The package therefore exports a
backend-conformance kit. Run it against your backend from your application's
own tests:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { assertBackendConformance } from "@open-e2ee/signal-protocol-sdk/local/store/key-value";

await assertBackendConformance({
  createBackend: () => createMyBackend(),
  // Optional: return a new instance over the same persistence medium to
  // verify committed writes survive reopen. Reported as skipped when absent.
  reopen: (previous) => reopenMyBackend(previous),
});
```

The function `assertBackendConformance` throws one error that names every
failing case. The function `runBackendConformance` returns the structured
result instead.

Continuous integration runs the kit against an in-memory reference backend on
the Hermes V1 command-line engine that React Native 0.86 uses, with only the
globals of a bare React Native app. Continuous integration also drives the
store over that backend through interruption and storage-pressure checks. The
reference backend is not part of the package. The parent
[storage guide](../README.md) holds the checklist that graduated this store.

Crash durability and backup behavior remain properties of your chosen native
storage engine, and key custody remains a property of your vault. The kit
verifies contract semantics, and your deployment review must still cover the
engine and the vault.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
