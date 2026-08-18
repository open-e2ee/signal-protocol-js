# Encrypted Profiles

The profile module generates profile keys, encrypts padded profile fields, and
stores the current user's profile key. It also tracks received contact profile
state and coordinates encrypted profile updates.

## Why it exists

Profile data is application content with its own key lifecycle. Profile keys
travel only through end-to-end encrypted messages. The profile service stores
encrypted fields and does not receive those keys.

## Usage

```ts
import {
  decryptProfileName,
  encryptProfileName,
  getOrCreateOwnProfileKey,
  setProfileKeyStorage,
} from "@open-e2ee/signal-protocol-sdk/profile";

setProfileKeyStorage(appProfileKeyStorage);

const profileKey = await getOrCreateOwnProfileKey();
const encryptedName = await encryptProfileName(profileKey, "Alice");
const { name } = await decryptProfileName(profileKey, encryptedName);
```

Use `updateEncryptedProfile()` to stage and upload an encrypted profile through
an application-owned API. Profile-key rotation is a coordinated operation.
Persist the new encrypted snapshot, distribute the new key through encrypted
messages, and retain enough local state to recover from interruption.

`appProfileKeyStorage` implements `ProfileKeyStorage` with `getItem`,
`setItem`, and `deleteItem`. Configure it before the first profile-key call.
The built-in React Native path uses Expo SecureStore. The browser fallback is
JavaScript-accessible localStorage. Node and server-side runtimes must provide a
persistent implementation if profile keys need to survive process restarts.
Storage confidentiality, backup, migration, and account-reset behavior remain
host-application responsibilities.

See the [security model](../docs/SECURITY.md) and
[API reference](../docs/api/README.md).
