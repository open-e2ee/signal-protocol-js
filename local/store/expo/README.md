# Expo Store

`ExpoSignalStore` implements `ISignalLocalStore` for Expo and React Native with
an application-owned SQLite/Drizzle database and a database key held through
the local secret-vault boundary.

## Why it exists

Signal Protocol state is larger and more transactional than platform keychains
are designed to hold. The adapter keeps a small database key in secure storage
and stores protocol records in the application's encrypted SQLite database.
The host owns database creation so it can compose these tables into its own
schema and transaction lifecycle.

## Database setup

Compose the exported table definitions into the application schema, configure
the database bindings once during bootstrap, and apply the database key before
the first query:

```ts
import {
  configureSignalExpoDbBindings,
} from "@open-e2ee/signal-protocol-sdk/local/store/expo/db";
import {
  getDatabaseKeyManager,
} from "@open-e2ee/signal-protocol-sdk/local/store/expo";
import * as signalSchema from "@open-e2ee/signal-protocol-sdk/local/store/expo/schema";

const keyManager = getDatabaseKeyManager();
await keyManager.initialize();
const sqlCipherPassword = await keyManager.getPassword();

const { rawDatabase, drizzleDatabase } =
  await appDatabase.openEncryptedSignalDatabase({
    password: sqlCipherPassword,
    schema: signalSchema,
  });

configureSignalExpoDbBindings({
  getDrizzle: async () => drizzleDatabase,
  getRawDatabase: () => rawDatabase,
});
```

`appDatabase.openEncryptedSignalDatabase` represents application-owned database
bootstrap. It must enable SQLCipher through the `expo-sqlite` native
configuration, apply the supplied key before schema access, create or migrate
the exported tables, and return the matching raw and Drizzle handles. SQLCipher
requires a development build and is not available in Expo Go.

## Client usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    storage: expoStore({ relay }),
    relay,
  },
});
```

The application must initialize database bindings before creating the client.
Account reset must remove the protocol tables, database key, device ownership
sentinel, and related secure-storage values as one lifecycle.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
the [Expo SQLite SQLCipher guide](https://docs.expo.dev/versions/latest/sdk/sqlite/#sqlcipher),
and [security model](../../../docs/SECURITY.md).
