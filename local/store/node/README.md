# Node Store

`NodeSignalProtocolStore` implements `SignalProtocolLocalStore` for Node and
the Electron main process in an SDK-owned SQLCipher database. The database key
is held through the local secret-vault boundary, in the vault that the app
passes.

## Why it exists

Servers, command-line tools, and desktop apps need persistent protocol state
without browser or mobile dependencies. The store keeps a small database key in
the vault and stores protocol records in an encrypted SQLite database. The SDK
owns that database: its file, its key, and its migrations.

## Setup

Install the peer `better-sqlite3-multiple-ciphers` 13.0.3 or later. The SDK
uses its SQLCipher cipher. Other entries do not load it.

```sh
npm install better-sqlite3-multiple-ciphers
```

Open the store with one call:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { nodeStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';

const storage = await nodeStore({
  directory: '/var/lib/my-app/signal-protocol',
  vault,
});
```

On first use, `nodeStore` creates the directory, readable only by the owner.
Then it creates a 32-byte database key, writes it to the vault, and creates the
database file. Each open applies the SDK migrations before it returns the
store. A file that a newer SDK wrote does not open (`INVALID_STATE`).

Options:

- `directory`: the directory of the database file. Use a private directory on
  a local file system. Do not use a network file system.
- `vault`: the `SignalProtocolLocalSecretVault` that holds the database key.
  Required. In Electron, use the safeStorage vault (see below). The store
  reports the custody of the vault in its `protection`. The level is
  `protected` with a vault that declares `os-keychain`, such as the
  safeStorage vault, or `app-vault`. A vault that declares no custody counts
  as `same-origin`, and the level is then `co-located`.
- `name`: the database file name in `directory`. Letters, digits, `.`, `_`,
  and `-` only, and no `.lock`, `-wal`, `-shm`, `-journal`, or
  `.oe2e-convert` ending. Default: `open-e2ee-signal-protocol.db`.
- `encryptionAtRest`: pass `false` to store the database without encryption.
  The store then does not use the vault, and it logs a warning at each open. A
  database created with one setting does not open with the other, except
  through `convertPlaintext`. The store reports `none` protection, so the
  client keeps no resendable content. Default: `true`.
- `convertPlaintext`: pass `true` to convert a plaintext database to an
  encrypted one at an encrypted open. See
  [Convert a plaintext store](#convert-a-plaintext-store). Default: `false`.
- `logger`: receives the warning of each open without encryption.

Keep application tables in a separate database file. The SDK database holds
only SDK tables.

## Electron

Use a supported Electron major: the Electron team supports the latest three
stable majors ([release timelines](https://www.electronjs.org/docs/latest/tutorial/electron-timelines)).
CI tests the latest major, Electron 44, on Linux, macOS, and Windows, and the
oldest supported major, Electron 42, on Linux. The binding uses Node-API,
so its prebuild loads in each supported major without a rebuild.

Open the store in the main process, with the vault over Electron's
`safeStorage`:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { join } from 'node:path';
import { app, safeStorage } from 'electron';
import { nodeStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';
import { ElectronSafeStorageSignalProtocolSecretVault } from '@open-e2ee/signal-protocol-sdk/local/vault/electron-safe-storage';

await app.whenReady();
const directory = join(app.getPath('userData'), 'signal-protocol');
const vault = new ElectronSafeStorageSignalProtocolSecretVault({
  safeStorage,
  file: join(app.getPath('userData'), 'signal-protocol-secrets.json'),
});
const storage = await nodeStore({ directory, vault });
```

The [vault guide](../../vault/README.md#electron-usage) covers the safeStorage
backends.

### Renderer

Do not open the store or the vault in a renderer or a preload script. Keep
the renderer defaults `contextIsolation: true`, `sandbox: true`, and
`nodeIntegration: false`. A renderer reaches the client through IPC:

- In the preload script, expose one function for each operation with
  `contextBridge`. Do not expose `ipcRenderer`.
- In the main process, check the `senderFrame` of each IPC message before it
  reaches the client.

See items 2, 3, 4, 17, and 20 of the
[security checklist](https://www.electronjs.org/docs/latest/tutorial/security).

### Utility process

The store can also run in a
[`utilityProcess`](https://www.electronjs.org/docs/latest/api/utility-process)
child. `safeStorage` is a main-process API, so the vault stays in the main
process:

1. In the main process, create a `MessageChannelMain`. Answer each
   `getSecret`, `setSecret`, and `deleteSecret` request on one port with the
   safeStorage vault.
2. Send the other port to the child with `child.postMessage(message, [port])`.
3. In the child, pass `nodeStore` a vault that sends each call over the port.

Only one process opens a database file (see [One owner](#one-owner)).

### Packaging

- **Unpack the binding.** The binding is a `.node` file. Electron loads a
  `.node` file from an ASAR archive through a temporary copy, and the copy
  stays after the app exits. With Electron Forge, add
  `@electron-forge/plugin-auto-unpack-natives`. Without Forge, pack with
  `asar pack app app.asar --unpack *.node`
  ([ASAR archives](https://www.electronjs.org/docs/latest/tutorial/asar-archives#adding-unpacked-files-to-asar-archives)).
- **Rebuild.** Electron Forge runs `@electron/rebuild`, which runs `node-gyp`
  for each native module. That needs Python and a C++ toolchain. The Node-API
  prebuild needs no rebuild. To package without a toolchain, set
  `rebuildConfig: { ignoreModules: ['better-sqlite3-multiple-ciphers'] }` in
  the Forge config.
- **Fuses.** Turn off the `RunAsNode`, `EnableNodeOptionsEnvironmentVariable`,
  and `EnableNodeCliInspectArguments` fuses. When they are on, a process of
  the same user can run code as the app, with `ELECTRON_RUN_AS_NODE` or
  `--inspect`. Through `--inspect`, that code can decrypt the vault with
  `safeStorage`. The Electron Forge templates turn them off
  ([fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)).
- **macOS signature.** Sign the app after the fuses are flipped and the
  package is complete. In an app whose signature is not valid, `safeStorage`
  fails, and the store then fails with `KEY_STORAGE_ERROR`. Check the app with
  `codesign --verify --deep --strict`. The
  [vault guide](../../vault/README.md#electron-usage) covers the signing
  identity.

## One owner

A store holds its database file until `close()`. Only one open store of a file
exists at a time:

- In the process that holds the file, an open or a reset of the same file
  fails with `INVALID_STATE`. The opens and resets of a file run one at a time,
  so two parallel first opens write one key, and the second open fails.
- Another process fails at once with `SqliteStoreInUseError`
  (`KEY_STORAGE_ERROR`). It does not read the vault or touch the file.

The owner lock is the file `<name>.lock` beside the database. The operating
system releases it when the process exits, also after a crash. Do not delete
the lock file while a process can use the store. A reset keeps it.

## Lost key and reset

The vault slot of the key is `sqliteDatabaseKeySlot(path)`, where `path` is
the real path of the database file. It is `join(realpathSync.native(directory),
name)`, so a symbolic link to the directory opens the same store with the same
key.

When the database file exists and the vault holds no key for it, `nodeStore`
fails with `LOCAL_STORE_KEY_LOST` and changes nothing. A new key cannot read
the old file. Restore the vault entry, or call `resetNodeStore()`.

A move or a rename of the directory changes the path, and with it the slot. The
next open fails with `LOCAL_STORE_KEY_LOST`, and the file does not change. To
keep the store, move the secret to the slot of the new path before the open:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { realpathSync } from 'node:fs';
import { join } from 'node:path';
import { sqliteDatabaseKeySlot } from '@open-e2ee/signal-protocol-sdk/local/store/node';

const name = 'open-e2ee-signal-protocol.db';
const from = sqliteDatabaseKeySlot(join(oldRealDirectory, name));
const to = sqliteDatabaseKeySlot(join(realpathSync.native(newDirectory), name));
const key = await vault.getSecret(from);
if (key) {
  await vault.setSecret(to, key);
  await vault.deleteSecret(from);
}
```

Finish a conversion before a move. The recipe moves only the main key, so a
conversion that a move interrupts cannot finish.

A file created with `encryptionAtRest: false` fails an open without that
option with `SqliteKeyMismatchError` (`KEY_STORAGE_ERROR`), not
`LOCAL_STORE_KEY_LOST`. Open it with the setting that created it, or convert
it to keep its data in an encrypted store.

`resetNodeStore()` deletes the database file, then writes a new key, then
returns the open, empty store. It takes the same options as `nodeStore`. Close
the open store of the file first.

`clearAllKeys()` on an open store empties every SDK table and keeps the file
and its key. `resetNodeStore()` is the full teardown.

## Convert a plaintext store

An encrypted open with `convertPlaintext: true` converts a database that was
created with `encryptionAtRest: false`:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { nodeStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';

const store = await nodeStore({ directory, vault, convertPlaintext: true });
```

The store keeps every row and its schema version, then applies the
migrations of this SDK. The option does nothing on an encrypted database or
when no file exists. With `encryptionAtRest: false`, the option fails with
`INVALID_STATE`.

The conversion writes a new key to a pending vault slot. It copies the
database to the encrypted temporary file `<name>.oe2e-convert` in one
transaction. Then it deletes the plaintext file and copies the temporary file
back. The delete of the plaintext file is the commit point. The conversion
needs free disk space for one more copy of the database. It runs inside the
owner lock.

The conversion refuses, with `INVALID_STATE`, a database that holds an
application table, a BLOB value, or an integer outside the safe JavaScript
range. It also refuses a file with no SDK schema. A file from a newer SDK
fails as at any open. A refusal changes nothing.

A crash or an error before the copy commits leaves the plaintext file. The
next open with the option starts again with a new key. A crash after the
commit point leaves the encrypted copy. The next encrypted open finishes the
conversion, with or without the option. While the temporary file exists,
an open or a reset with `encryptionAtRest: false` fails with `INVALID_STATE`.

The open fails with `INVALID_STATE` and names both files when the plaintext
file and a complete encrypted copy both exist. A crash between the end of the
copy and the commit point leaves this state. So does an older SDK that opens
the store after the commit point. Delete the plaintext file and its `-wal`,
`-shm`, and `-journal` files, then open again. The open then finishes the
conversion from the copy. An
encrypted reset also ends any conversion, and it deletes all data.

Residual risks:

- The disk blocks of the old plaintext file can keep plaintext until the file
  system reuses them. So can backups and file system snapshots. The SDK cannot
  erase them.
- A directory move during a conversion is not supported. The open then fails
  with `INVALID_STATE`, because the temporary file has no key at the new path.
  Move the directory back and open it there.
- An SDK older than this release does not know the temporary file. If it
  opens the store after the commit point, it creates a new empty store.

## Data protection

Every table in this store holds material that must not leave the device.
That includes the group `sender_keys` and `skipped_sender_keys` tables. Their
rows contain the sender chain key, the sender's private signature key, and
individual message keys. That material is enough to read and to forge a
sender's group messages. The store writes those rows unencrypted at the row
level, because SQLCipher encrypts the database file itself. The database key is
therefore the only thing that protects them.

The app still owns OS account isolation, backups, volume security, and process
access. Do not back up the database file to a server or sync it between
devices.

## Client usage

<!-- doc-snippet:skip requires-external-context -->

```ts
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { nodeStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage: await nodeStore({ directory, vault }), relay },
});
```

For replaced-prekey maintenance, pass the open store to
`createPreKeyMaintenanceStore(store)`.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
