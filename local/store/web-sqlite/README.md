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
  letters, digits, `.`, `_`, and `-`. It also names the vault slot of the key.
  Default: `open-e2ee-signal-protocol.db`.
- `vault`: the `SignalProtocolLocalSecretVault` that holds the database key.
  Default: the SDK's IndexedDB vault in the same origin.
- `encryptionAtRest`: pass `false` to store the database without encryption.
  The store then does not use the vault, and it logs a warning at each open. A
  database created with one setting does not open with the other. Default:
  `true`.
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
WKWebView on macOS and iOS. A manual check ran it with Tauri 2.12 on macOS
15.7 and in the iOS 18.0 simulator. No CI job runs it in Tauri. It needs no
Tauri headers (`app.security.headers`) and no capability, because the store
makes no IPC call.

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
- **Linux.** WebKitGTK 2.54 has no OPFS synchronous access handles. On it,
  the expected result of the open is a rejection with `OPFS_UNAVAILABLE`. See
  [When OPFS is not available](#when-opfs-is-not-available).
- **Windows and Android.** WebView2 and the Android WebView are not yet
  tested.
- **Key custody.** The default vault keeps the key in IndexedDB in the same
  origin as the database. An app that needs OS keychain custody passes its own
  vault. See [Security boundary](#security-boundary).

## Security boundary

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

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
