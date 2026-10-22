# Web SQLite Store

`webSqliteStore` opens a `SignalProtocolLocalStore` on SQLite in the browser.
The engine is SQLite3 Multiple Ciphers, compiled to WebAssembly. It runs in
one dedicated module worker, and each database file lives in the origin
private file system (OPFS). The file is encrypted in the SQLCipher 4 format
with a 32-byte key that the store keeps in a secret vault.

## Setup

Install the peer `idb` 8.0.3 or later. The default vault keeps the database
key in IndexedDB through it. The entry loads it also when the app passes its
own vault.

```sh
npm install idb
```

## Usage

<!-- doc-snippet:skip requires-external-context -->

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { webSqliteStore } from "@open-e2ee/signal-protocol-sdk/local/store/web-sqlite";

const storage = await webSqliteStore();

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

On first use, `webSqliteStore` creates a 32-byte database key, writes it to
the vault, and then creates the database file. Each open applies the SDK
migrations before it returns the store. A file that a newer SDK wrote does not
open (`INVALID_STATE`).

Options:

- `name`: the database name in OPFS. A letter or digit, then up to 63
  letters, digits, `.`, `_`, and `-`, and no `.oe2e-convert` ending. It also
  names the vault slot of the key. A conversion with `convertPlaintext` needs
  a name of at most 51 characters. Default: `open-e2ee-signal-protocol.db`.
- `vault`: the `SignalProtocolLocalSecretVault` that holds the database key.
  Default: the SDK's IndexedDB vault in the same origin.
- `encryptionAtRest`: pass `false` to store the database without encryption.
  The store then does not use the vault, and it logs a warning at each open. A
  database created with one setting does not open with the other, except
  through `convertPlaintext`. Default: `true`.
- `convertPlaintext`: pass `true` to convert a plaintext database to an
  encrypted one at an encrypted open. See
  [Convert a plaintext store](#convert-a-plaintext-store). Default: `false`.
- `logger`: receives the warning of each open without encryption.
- `workerUrl` and `wasmUrl`: see [Content Security Policy](#content-security-policy).

Each store runs its own worker. Close the store with `close()`: it closes the
database and stops the worker. A failed open also stops its worker. Keep
application tables in a separate
database. The SDK database holds only SDK tables.

## Lost key and reset

When the database file exists and the vault holds no key for it,
`webSqliteStore` fails with `LOCAL_STORE_KEY_LOST` and changes nothing. A new
key cannot read the old file. Restore the vault entry, or call
`resetWebSqliteStore()`. The reset deletes the file, creates a new key, and
returns the open, empty store.

## Convert a plaintext store

An encrypted open with `convertPlaintext: true` converts a database that was
created with `encryptionAtRest: false`:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { webSqliteStore } from '@open-e2ee/signal-protocol-sdk/local/store/web-sqlite';

const store = await webSqliteStore({ convertPlaintext: true });
```

The store keeps every row and its schema version, then applies the
migrations of this SDK. The option does nothing on an encrypted database or
when no database exists. With `encryptionAtRest: false`, the option fails with
`INVALID_STATE`.

A database created with `encryptionAtRest: false` fails an open without the
option with `SqliteKeyMismatchError` (`KEY_STORAGE_ERROR`). Open it with the
setting that created it, or convert it to keep its data in an encrypted store.

The conversion writes a new key to a pending vault slot. It copies the
database to the encrypted temporary database `<name>.oe2e-convert` in one
transaction. Then it deletes the plaintext database and copies the temporary
database back. The delete of the plaintext database is the commit point. The
conversion needs storage quota for one more copy of the database.

Each database file has its own OPFS directory, `.open-e2ee-sqlite-<name>`.
When the store removes a database file, it also removes that directory if no
other file of the store is in it. This applies to the conversion and to a
reset. So a finished conversion leaves no directory for
`<name>.oe2e-convert`. If the browser does not remove the directory, the
directory stays, and the next use of the name uses it again. A check for a
database that does not exist leaves no directory.

The conversion needs the store of the name in no other tab or worker of the
origin. While another context has it open, the conversion fails at once with
`INVALID_STATE` and changes nothing. A name longer than 51 characters also
fails with `INVALID_STATE` before any write.

The conversion refuses, with `INVALID_STATE`, a database that holds an
application table, a BLOB value, or an integer outside the safe JavaScript
range. It also refuses a database with no SDK schema. A database from a newer
SDK fails as at any open. A refusal changes nothing.

A crash or an error before the copy commits leaves the plaintext database.
The next open with the option starts again with a new key. A crash after the
commit point leaves the encrypted copy. The next encrypted open finishes the
conversion, with or without the option. While the temporary database exists,
an open or a reset with `encryptionAtRest: false` fails with `INVALID_STATE`.

The open fails with `INVALID_STATE` and names both databases when the
plaintext database and a complete encrypted copy both exist. A crash between
the end of the copy and the commit point leaves this state. So does an older
SDK that opens the store after the commit point. The store has no call that
deletes one database of the pair. An encrypted reset ends the state, and it
deletes all data.

Residual risk: an SDK older than this release does not know the temporary
database. If it opens the store after the commit point, it creates a new
empty store.

## Tabs

Each tab opens its own store, and the tabs of an origin share the database.
One worker at a time holds the file. A tab that needs the file asks the
holder, and the holder hands it over after its current statement, never in a
transaction. Each tab reads the writes of the other tabs.

- The opens and resets of a name run one at a time in the origin, so two tabs
  that open a new store at the same time write one key.
- A second open of a name in the same tab or worker, while its store is open,
  fails with `INVALID_STATE`.
- A reset fails with `INVALID_STATE` while a store of the name is open in any
  tab or worker of the origin. Close it everywhere first.
- A store fails with `INVALID_STATE` when another tab changed the schema
  version of the file while it waited, for example a tab with a newer SDK.
  Close the store and open it again.
- `OPFS_FILE_BUSY` means that another tab or worker of the origin still holds
  the files, for example a tab that is closing. The file is unchanged. Retry
  the open later.
  The store already retries a transient failure of the origin private file
  system a few times before it rejects with this code.

## Full storage

When the origin storage quota is full, the open rejects with
`StorageQuotaExceededError` (`STORAGE_QUOTA_EXCEEDED`). An open that fails
this way on a new store writes no key and no database file. A write on an open
store rejects with the same error. SQLite rolls the write back, and the store
stays open. Free space, then open again or retry the write.

## Content Security Policy

The engine compiles WebAssembly in its worker. A Content Security Policy
that applies to the worker must allow it with `'wasm-unsafe-eval'` in
`script-src`. The store needs no other relaxation: no `'unsafe-eval'`, no
`blob:` worker, and no inline script.

```text
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'
```

- Send the header on the worker script response. A module worker takes the
  policy of its own response, not the policy of the page. A site that sends
  one policy on every response adds `'wasm-unsafe-eval'` to that policy.
- `worker-src` must allow the worker script, and `connect-src` must allow
  the Wasm file.
- Serve `sqlite3.wasm` as `application/wasm`.
- Emit the worker and `sqlite3mc/sqlite3.wasm` next to the module that
  creates the driver, as the package lays them out. Most bundlers resolve
  the default URLs. Otherwise pass `workerUrl` and `wasmUrl`.

Without `'wasm-unsafe-eval'`, the open rejects with
`SQLITE_ENGINE_UNAVAILABLE`.

## When OPFS is not available

Some browser contexts cannot keep a file in OPFS: some private or ephemeral
contexts, WebKit on Linux, and other runtimes without synchronous access
handles in a worker. The open then rejects with `OPFS_UNAVAILABLE` before it
loads the engine. Use the IndexedDB store in that runtime:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { EncryptionError, EncryptionErrorCode } from "@open-e2ee/signal-protocol-sdk";
import { indexedDbStore } from "@open-e2ee/signal-protocol-sdk/local/store/web";
import { webSqliteStore } from "@open-e2ee/signal-protocol-sdk/local/store/web-sqlite";

async function openStorage() {
  try {
    return await webSqliteStore();
  } catch (error) {
    if (error instanceof EncryptionError && error.code === EncryptionErrorCode.OPFS_UNAVAILABLE) {
      return indexedDbStore();
    }
    throw error;
  }
}
```

The two stores do not share data. Choose one for each runtime, and do not
move to the other after an error that is not `OPFS_UNAVAILABLE`.

## Tauri

A Tauri 2 app uses this entry in its webview. The entry runs unchanged in
WebView2 on Windows, in the Android WebView, and in WKWebView on macOS and iOS.
A CI job runs it in a Tauri 2.12 app in WebView2 on Windows and in the Android
WebView on an Android emulator. Manual checks ran it with Tauri 2.12 on
macOS 15.7 and in the iOS 17.5 and 18.0 simulators. It needs no Tauri headers
(`app.security.headers`) and no capability, because the store makes no IPC
call.

Put the policy from [Content Security Policy](#content-security-policy) in
`app.security.csp` of `tauri.conf.json`. When the app uses Tauri IPC, add the
IPC sources to `connect-src`:

```json
{
  "app": {
    "security": {
      "csp": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' ipc: http://ipc.localhost"
    }
  }
}
```

- **Policy scope.** Tauri sends `app.security.csp` only with the HTML files
  that it serves from `frontendDist`, and it adds the hashes of its scripts to
  `script-src`. The worker script and `sqlite3.wasm` get no policy, and
  `app.security.headers` cannot set one. The page policy must allow the worker
  in `worker-src`. With a `devUrl`, `tauri dev` loads the page from the dev
  server, and the policy does not apply. Test the policy on a build.
- **IPC on Windows and Android.** When `useHttpsScheme` is `true`, the IPC
  source is `https://ipc.localhost`. Put it in `connect-src` in place of
  `http://ipc.localhost`.
- **Origin.** The database and the vault belong to the origin of the webview.
  On Windows and Android, `useHttpsScheme` of the window
  (`app.windows[].useHttpsScheme`) sets that origin. `dataDirectory` (Windows
  and Linux) and `dataStoreIdentifier` (macOS 14 and iOS 17 or later) set
  where the webview keeps its data. Set these values before the first release,
  and never change them. A change moves the data, and the app then cannot find
  its database or its vault.
- **Windows of one app.** Each window of the app is its own JavaScript
  context. The windows of one origin share the database. A reset fails
  with `INVALID_STATE` while any window holds the store. See [Tabs](#tabs).
- **Website data.** The database and the vault key are website data of the
  webview. In WKWebView, `navigator.storage.persist()` returns `false`, so
  the webview does not promise to keep them. A clear of all website data,
  for example with `clear_all_browsing_data`, removes the database and the
  key together. The next open then creates a new, empty store and reports
  no error. The open fails with `LOCAL_STORE_KEY_LOST` only when the file
  stays and the key goes. See [Lost key and reset](#lost-key-and-reset).
- **Loss of all data.** The app must find a loss of all website data itself.
  For example, write a marker to the store with `setMetadata`. Keep a record
  in the app data directory, outside the webview data, that the device has a
  store. When the record exists and the marker does not, treat the device as
  a new device. Do not clear the website data of the webview that holds the
  store.
- **Linux.** WebKitGTK has no OPFS synchronous access handles, so the open
  rejects with `OPFS_UNAVAILABLE`. A CI job checks this refusal in a Tauri
  app with WebKitGTK 2.52. See
  [When OPFS is not available](#when-opfs-is-not-available).
- **Android.** A CI job runs every check in a debug APK in the Android
  WebView 133 on an Android API 36 emulator, and every check passes. The
  origin of the webview is `http://tauri.localhost`.
- **Key custody.** The default vault keeps the key in IndexedDB in the same
  origin as the database, so the store reports `same-origin` custody. An app
  that needs other custody passes its own vault. See
  [Security boundary](#security-boundary).

## Security boundary

Reviewed: 2026-10-12.

The default vault keeps the database key as raw bytes in IndexedDB, in the
same origin as the database file. The key protects a copy of the database
file that does not also include that IndexedDB record. It does not protect
against script that runs in the origin (XSS), a browser extension with
access to the site, malware that reads the browser profile, or a copy of the
full profile. Encryption at rest is therefore not an XSS defense. See the
[IndexedDB store guide](../web/README.md#security-boundary) for the
origin-security controls that a deployment needs.

An application with a different key custody passes its own
`SignalProtocolLocalSecretVault` as `vault`.

The store reports its `protection` from the database file and the vault:
`file-cipher` with the custody of the vault, or `none` with
`encryptionAtRest: false`. With the default vault, the level is
`co-located`. The default content recovery mode, `require-protected`, then
keeps no resendable content. Set `protocol.contentRecovery.mode` to
`allow-co-located-key` only after a product review accepts that key
custody, or pass a vault that declares `os-keychain` or `app-vault`. See
[Content Recovery](../../../docs/PROTOCOL_POLICY.md#content-recovery).

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
