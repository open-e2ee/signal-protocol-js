import { drizzle } from 'drizzle-orm/expo-sqlite';
import { migrate } from 'drizzle-orm/expo-sqlite/migrator';
import { openDatabaseAsync } from 'expo-sqlite';
import { expoStore, getDatabaseKeyManager } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
import { configureSignalProtocolExpoDbBindings } from '@open-e2ee/signal-protocol-sdk/local/store/expo/db';
import * as schema from '@open-e2ee/signal-protocol-sdk/local/store/expo/schema';
import migrations from './drizzle/migrations.json';

type ExampleState = { attempts: number; completed: number; identity_public: string | null };
let opened: ReturnType<typeof openStore> | undefined;

export function openAliceStore() {
  opened ??= openStore().catch((error) => { opened = undefined; throw error; });
  return opened;
}

async function openStore() {
  const keyManager = getDatabaseKeyManager();
  await keyManager.initialize();
  const password = await keyManager.getPassword();
  if (!/^x'[0-9a-f]{64}'$/i.test(password)) throw new Error('The database key has an invalid format.');
  const raw = await openDatabaseAsync('opene2ee-alice.db');
  await raw.execAsync(`PRAGMA key = "${password}";`);
  const cipher = await raw.getFirstAsync<{ cipher_version: string }>('PRAGMA cipher_version');
  if (!cipher?.cipher_version) throw new Error('SQLCipher is unavailable. Build the native app with useSQLCipher enabled.');
  const db = drizzle(raw, { schema });
  await migrate(db, migrations);
  configureSignalProtocolExpoDbBindings({ getDrizzle: async () => db, getRawDatabase: () => raw });
  const store = expoStore();

  return {
    store,
    async start(log: (line: string) => void) {
      log(`SQLCipher ${cipher.cipher_version}: Alice uses an encrypted device-local store.`);
      await raw.runAsync('INSERT OR IGNORE INTO example_state (id, attempts, completed) VALUES (1, 0, 0)');
      const state = (await raw.getFirstAsync<ExampleState>('SELECT * FROM example_state WHERE id = 1'))!;
      const identity = await store.getIdentityKey();
      if (state.identity_public && identity?.dhKey.publicKey !== state.identity_public) {
        throw new Error('The stored Alice identity did not match the previous run.');
      }
      if (state.identity_public) log(`Resumed Alice identity after ${state.completed} completed exchanges.`);
      else log('Create the first persistent Alice identity.');
      await raw.runAsync('UPDATE example_state SET attempts = attempts + 1 WHERE id = 1');
      return state.attempts + 1;
    },
    async complete(log: (line: string) => void) {
      const identity = await store.getIdentityKey();
      if (!identity) throw new Error('Alice has no stored identity after the exchange.');
      await raw.runAsync('UPDATE example_state SET completed = completed + 1, identity_public = ? WHERE id = 1', identity.dhKey.publicKey);
      log('Alice identity and session state remain in SQLCipher. Close and reopen the app to check persistence.');
    },
  };
}
