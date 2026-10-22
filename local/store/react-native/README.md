# React Native SQLite Store

`ReactNativeSignalProtocolStore` implements `SignalProtocolLocalStore`
for bare React Native in an SDK-owned SQLCipher database on
[op-sqlite](https://github.com/OP-Engineering/op-sqlite). The database key is
held through the local secret-vault boundary, by default in the
react-native-keychain vault.

## Why it exists

Signal Protocol state is larger and more transactional than the values
platform keychains hold. The store keeps a small database key in the keychain
and stores protocol records in an encrypted SQLite database. The SDK owns that
database: its file, its key, and its migrations.

## Setup

Install the two optional peers:

<!-- doc-snippet:skip requires-external-context -->

```sh
npm install @op-engineering/op-sqlite react-native-keychain
```

Turn on the op-sqlite SQLCipher build in the `package.json` of the app, then
run `pod install` and rebuild the app:

<!-- doc-snippet:skip requires-external-context -->

```json
{
  "op-sqlite": {
    "sqlcipher": true
  }
}
```

Without that flag, op-sqlite cannot apply the database key, and the open fails
before it creates a file.

With SQLCipher on, op-sqlite conflicts on iOS with:

- `expo-sqlite`, which also links SQLite. Do not install both in one app.
- `expo-updates`, which also links SQLite. When it is the only conflict, add
  `"expo.updates.useThirdPartySQLitePod": "true"` to
  `ios/Podfile.properties.json`.
- `use_frameworks!` in the Podfile, which breaks the build or makes it use
  the embedded SQLite of iOS, which has no cipher.

op-sqlite works in an Expo prebuild (development or release build), not in
Expo Go. An Expo app can use the [Expo store](../expo/README.md) instead.

Open the store with one call:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { reactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';

const storage = await reactNativeStore();
```

On first use, `reactNativeStore` creates a 32-byte database key, writes
it to the vault, and then creates the database file. Each open applies the SDK
migrations before it returns the store. A file that a newer SDK wrote does not
open (`INVALID_STATE`).

Options:

- `name`: the database file name in the op-sqlite default location (the
  Library directory on iOS, the databases directory on Android). Letters,
  digits, `.`, `_`, and `-` only, and no `.oe2e-convert` ending. Default:
  `open-e2ee-signal-protocol.db`.
- `vault`: the `SignalProtocolLocalSecretVault` that holds the database key.
  Default: `ReactNativeKeychainSignalProtocolSecretVault`, which keeps the key
  on this device only (see the [vault guide](../../vault/README.md)).
- `encryptionAtRest`: pass `false` to store the database without encryption.
  The store then does not use the vault, and it logs a warning at each open. A
  database created with one setting does not open with the other, except
  through `convertPlaintext`. Default: `true`, and the open fails when
  op-sqlite is not built with SQLCipher.
- `convertPlaintext`: pass `true` to convert a plaintext database to an
  encrypted one at an encrypted open. See
  [Convert a plaintext store](#convert-a-plaintext-store). Default: `false`.
- `logger`: receives the warning of each open without encryption.

A store holds its name until `close()`. In one process, the opens and resets
of a name run one at a time. An open or a reset of a name that an open store
holds fails with `INVALID_STATE`, so two parallel first opens write one key
and the second open fails.

Keep application tables in a separate database file. The SDK database holds
only SDK tables.

## Lost key and reset

When the database file exists and the vault holds no key for it,
`reactNativeStore` fails with `LOCAL_STORE_KEY_LOST` and changes nothing.
A new key cannot read the old file. Restore the vault entry, or call
`resetReactNativeStore()`.

A file created with `encryptionAtRest: false` fails an open without that
option with `SqliteKeyMismatchError` (`KEY_STORAGE_ERROR`), not
`LOCAL_STORE_KEY_LOST`. Open it with the setting that created it, or convert
it to keep its data in an encrypted store (see
[Convert a plaintext store](#convert-a-plaintext-store)).

`resetReactNativeStore()` deletes the database file, then writes a new
key, then returns the open, empty store. It takes the same options as
`reactNativeStore`. Close the open store of the name first.

`clearAllKeys()` on an open store empties every SDK table and keeps the file
and its key. `resetReactNativeStore()` is the full teardown.

## Convert a plaintext store

An encrypted open with `convertPlaintext: true` converts a database that was
created with `encryptionAtRest: false`:

<!-- doc-snippet:skip requires-external-context -->

```ts
import { reactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';

const store = await reactNativeStore({ convertPlaintext: true });
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
open, one at a time with the other opens and resets of the name.

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
  system reuses them. So can device backups. The SDK cannot erase them.
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

Do not back up the database file to a server or sync it between devices. The
default vault keeps the key out of device backups. iOS backs up the Library
directory, and Android Auto Backup includes the databases directory unless the
app excludes it. A file restored from a backup to a new device therefore has no
key there, and the open fails with `LOCAL_STORE_KEY_LOST`.

## Client usage

<!-- doc-snippet:skip requires-external-context -->

```ts
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { reactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage: await reactNativeStore(), relay },
});
```

For replaced-prekey maintenance, pass the open store to
`createPreKeyMaintenanceStore(store)`.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
the [op-sqlite installation guide](https://op-engineering.github.io/op-sqlite/docs/installation),
and [security model](../../../docs/SECURITY.md).
