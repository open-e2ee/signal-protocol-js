import { open } from '@op-engineering/op-sqlite';
import { reactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';
import { checkEncryptionAtRest, checkWrongKey } from './encryption';

type ExampleState = { attempts: number; completed: number; identity_public: string | null };
let opened: ReturnType<typeof openStore> | undefined;

export function openAliceStore() {
  opened ??= openStore().catch((error) => { opened = undefined; throw error; });
  return opened;
}

async function openStore() {
  // The keychain holds the database key. SQLCipher encrypts the whole file.
  const store = await reactNativeStore();
  // The example's run counters live in their own file. The SDK database
  // holds only SDK tables.
  const state = open({ name: 'opene2ee-example-state.db' });
  state.executeSync(
    'CREATE TABLE IF NOT EXISTS example_state (id INTEGER PRIMARY KEY, attempts INTEGER NOT NULL, completed INTEGER NOT NULL, identity_public TEXT)'
  );

  function read(): ExampleState {
    state.executeSync('INSERT OR IGNORE INTO example_state (id, attempts, completed) VALUES (1, 0, 0)');
    return state.executeSync('SELECT * FROM example_state WHERE id = 1').rows[0] as ExampleState;
  }

  return {
    store,
    async start(log: (line: string) => void) {
      log('Alice uses the SDK-owned SQLite store on op-sqlite, with its database key in the keychain.');
      await checkEncryptionAtRest(state, log);
      await checkWrongKey(log);
      const previous = read();
      const identity = await store.getIdentityKey();
      if (previous.identity_public && identity?.dhKey.publicKey !== previous.identity_public) {
        throw new Error('The stored Alice identity did not match the previous run.');
      }
      if (previous.identity_public) log(`Resumed Alice identity after ${previous.completed} completed exchanges.`);
      else log('Create the first persistent Alice identity.');
      state.executeSync('UPDATE example_state SET attempts = attempts + 1 WHERE id = 1');
      return previous.attempts + 1;
    },
    async complete(log: (line: string) => void) {
      const identity = await store.getIdentityKey();
      if (!identity) throw new Error('Alice has no stored identity after the exchange.');
      state.executeSync('UPDATE example_state SET completed = completed + 1, identity_public = ? WHERE id = 1', [
        identity.dhKey.publicKey,
      ]);
      log('Alice identity and session state remain in the SQLite store. Close and reopen the app to check persistence.');
    },
  };
}
