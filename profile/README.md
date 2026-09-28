# Encrypted Profiles

The profile module generates profile keys, encrypts padded profile fields, and
stores the current user's profile key. It also tracks received contact profile
state and coordinates encrypted profile updates.

## Why it exists

Profile data is application content with its own key lifecycle. Profile keys
travel only through end-to-end encrypted messages. The profile service stores
encrypted fields and does not receive those keys.

## Usage

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  decryptProfileName,
  encryptProfileName,
  getOrCreateOwnProfileKey,
} from "@open-e2ee/signal-protocol-sdk/profile";

const profileKey = await getOrCreateOwnProfileKey(secretVault);
const encryptedName = await encryptProfileName(profileKey, "Alice");
const { name } = await decryptProfileName(profileKey, encryptedName);
```

Use `updateEncryptedProfile()` to stage and upload an encrypted profile through
an application-owned API. Profile-key rotation is a coordinated operation.
Persist the new encrypted snapshot, distribute the new key through encrypted
messages, and retain enough local state to recover from interruption.

`secretVault` is the `SignalProtocolLocalSecretVault` that the application
passes to every own-profile-key call. The key is kept only in that vault, as
its raw 32 bytes. On Expo, use `ExpoSecureStoreSignalProtocolSecretVault` from
`@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store`. Other runtimes
pass their own implementation. The SDK has no fallback store: it never writes
the key to `localStorage`, and a call with no vault throws an `EncryptionError`
with code `SECRET_VAULT_REQUIRED`. Storage confidentiality, backup, migration,
and account-reset behavior remain host-application responsibilities.

See the [security model](../docs/SECURITY.md) and
[API reference](../docs/api/README.md).
