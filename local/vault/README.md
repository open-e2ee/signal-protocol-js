# Local Secret Vault

The local secret vault stores small bootstrap secrets through a minimal
`getSecret` / `setSecret` / `deleteSecret` interface.

## Why it exists

Platform secret managers are appropriate for tiny keys and bootstrap values,
but not full session databases. Separating the vault from
`ISignalLocalStore` keeps platform limits explicit and lets a local store use a
vault-held wrapping key without placing every protocol record in the platform
keychain.

## Expo usage

```ts
import { ExpoSecureStoreSignalSecretVault } from "@open-e2ee/signal-protocol-sdk/local/vault/expo-secure-store";

const vault = new ExpoSecureStoreSignalSecretVault();

await vault.setSecret("signal-store-wrapping-key", wrappingKey);
const restored = await vault.getSecret("signal-store-wrapping-key");
```

Secret names are application-wide storage keys. Namespace them to avoid
collisions and delete them during the same account-reset transaction as the
encrypted local store. Platform backup, biometric access, and device-migration
behavior remain application decisions.

See the [local-store guide](../store/README.md) and
[adapter guide](../../ADAPTERS.md).

