# Local Secret Vault

The local secret vault stores small bootstrap secrets through a minimal
`getSecret` / `setSecret` / `deleteSecret` interface.

## Why it exists

Platform secret managers are appropriate for tiny keys and bootstrap values,
but not full session databases. A vault separate from
`SignalProtocolLocalStore` keeps platform limits explicit. A local store can
then use a vault-held wrapping key without placing every protocol record in the
platform keychain.

## Expo usage

Install the optional peer `expo-secure-store` 55.0.15 or later.

```sh
npx expo install expo-secure-store
```

<!-- doc-snippet:skip requires-external-context -->
```ts
import { ExpoSecureStoreSignalProtocolSecretVault } from "@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store";

const vault = new ExpoSecureStoreSignalProtocolSecretVault();

await vault.setSecret("signal-store-wrapping-key", wrappingKey);
const restored = await vault.getSecret("signal-store-wrapping-key");
```

## Bare React Native usage

Install the optional peer `react-native-keychain` 10.0.0 or later.

```sh
npm install react-native-keychain
```

<!-- doc-snippet:skip requires-external-context -->
```ts
import { ReactNativeKeychainSignalProtocolSecretVault } from "@open-e2ee/signal-protocol-sdk/local/vault/react-native-keychain";

const vault = new ReactNativeKeychainSignalProtocolSecretVault();

await vault.setSecret("signal-store-wrapping-key", wrappingKey);
const restored = await vault.getSecret("signal-store-wrapping-key");
```

The secret name is the keychain service, and the value is stored as lowercase
hex. The adapter rejects an empty name, an empty value, and a stored value that
is not lowercase hex with an `EncryptionError` that has the code
`KEY_STORAGE_ERROR`.

The adapter sets these options on every write. The application cannot change
them:

| Option | Value | Why |
| --- | --- | --- |
| `accessible` (iOS) | `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` | The item stays on this device. It is not in iCloud Keychain or in a backup that restores to another device. A background task can read it after the first unlock. |
| `storage` (Android) | `AES_GCM_NO_AUTH` | The value is encrypted with AES-GCM under a key in the Android Keystore. No biometric prompt. |
| `securityLevel` (Android) | `SECURE_SOFTWARE` | The key must be in the Android Keystore, apart from the data. `SECURE_HARDWARE` fails on emulators and on devices with a software keymaster, and the library checks it only when it makes a new key. `ANY` removes the Keystore check. |
| `cloudSync` (iOS) | not set | react-native-keychain 10.0.0 turns iCloud sync on when this key has any value, `false` included ([issue #800](https://github.com/oblador/react-native-keychain/issues/800)). |

With these options the key does not leave the device.

On iOS, a write deletes the existing item and then adds the new one, so a
write is not atomic. A crash between the two steps leaves no item.

## Electron usage

Use the vault in the main process, after the app is ready. The app passes its
own `safeStorage`, so the SDK does not import `electron`.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { join } from "node:path";
import { app, safeStorage } from "electron";
import { ElectronSafeStorageSignalProtocolSecretVault } from "@open-e2ee/signal-protocol-sdk/local/vault/electron-safe-storage";

await app.whenReady();
const vault = new ElectronSafeStorageSignalProtocolSecretVault({
  safeStorage,
  file: join(app.getPath("userData"), "signal-protocol-secrets.json"),
});

await vault.setSecret("signal-store-wrapping-key", wrappingKey);
const restored = await vault.getSecret("signal-store-wrapping-key");
```

`safeStorage` encrypts each secret under a key that the OS holds: the macOS
Keychain, Windows DPAPI, or the Linux secret store. The vault keeps only the
ciphertexts, as base64 in a JSON file that the app names. The file's directory
must exist, and one vault owns the file. Each write replaces the file
atomically, and the file is readable only by the owner.

The protection is that of the OS key store
([safeStorage](https://www.electronjs.org/docs/latest/api/safe-storage)):

- **macOS.** The Keychain protects the key from other users and from other
  apps of the same user.
- **Windows.** DPAPI protects the key from other users. It does not protect it
  from other apps of the same user.
- **Linux.** A secret service, for example GNOME Keyring or KWallet, must run
  and be reachable over D-Bus. When no secret service is reachable,
  `safeStorage` encrypts with a fixed key, and
  `getSelectedStorageBackend()` can still return `gnome_libsecret`. The vault
  refuses that key: on Linux, it accepts only a ciphertext that starts with
  `v11`, the prefix of a key from a secret service.

On Linux, the vault gives these results for the backends of
`getSelectedStorageBackend()`:

| Backend | Secret store | Result |
|---|---|---|
| `gnome_libsecret` | GNOME Keyring | The vault works. |
| `kwallet5` | KWallet 5, and KWallet 6 through its `kwalletd5` name | The vault works. |
| `kwallet6` | KWallet 6 | The vault works. |
| `basic_text` | None | The vault refuses the backend. |
| `gnome_libsecret`, `kwallet5`, or `kwallet6` with no secret service | None: the fixed fallback key, `v10` | The vault refuses the key. |
| `gnome_libsecret`, `kwallet5`, or `kwallet6`, with the Chromium feature `SecretPortalKeyProviderUseForEncryption` and a Secret portal | The key of the Secret portal, `v12` | The vault refuses the key. |

The Secret portal of xdg-desktop-portal gives a key to each app. Outside a
Flatpak or Snap sandbox, Electron asks for the key as the Chromium app. Each
Electron app of the user then gets the same key. Electron uses the portal key
only with the `SecretPortalKeyProviderUseForEncryption` feature, which is off
by default. Without that feature, a running portal does not change the key.

The vault fails with an `EncryptionError` that has the code
`KEY_STORAGE_ERROR`:

- when async encryption is not available, which is the case before the app is
  ready;
- on Linux, when the backend is `basic_text`, which encrypts with a fixed
  password, or `unknown`;
- on Linux, when a ciphertext does not start with `v11`, for example when no
  secret service answered and `safeStorage` used its fixed key, or when
  `safeStorage` used the key of the Secret portal. The vault file does not
  change;
- when `safeStorage` cannot encrypt or decrypt, for example when the OS key
  is gone or the macOS signature of the app is not valid. The Electron error
  is the `originalError`. It can say that `safeStorage` is temporarily
  unavailable. The vault file does not change.

Use the vault only in the main process. `safeStorage` is not available in a
renderer, a preload script, or a `utilityProcess`. A store in a
`utilityProcess` reaches the vault over a message port (see the
[Node store guide](../store/node/README.md#utility-process)).

On macOS, sign every build with the same identity, and notarize the app
([code signing](https://www.electronjs.org/docs/latest/tutorial/code-signing#macos-apis-that-require-code-signing)).
A build with a different signature can make the Keychain ask the user again.
An ad-hoc signature changes with each build.

## Secret names

Secret names are application-wide storage keys. Namespace them to avoid
collisions and delete them during the same account-reset transaction as the
encrypted local store. Each adapter keeps the item on this device, so a new
device does not receive it. Biometric access and device migration remain
application decisions.

See the [local-store guide](../store/README.md) and
[adapter guide](../../ADAPTERS.md).

