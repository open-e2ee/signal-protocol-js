import { File } from 'expo-file-system';
import { defaultDatabaseDirectory, openDatabaseAsync, type SQLiteDatabase } from 'expo-sqlite';
import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';

type ExampleState = { attempts: number; completed: number; identity_public: string | null };
let opened: ReturnType<typeof openStore> | undefined;

// The file that expoStore() opens when the options name none.
const SDK_DATABASE_NAME = 'open-e2ee-signal-protocol.db';
const PLAINTEXT_HEADER = 'SQLite format 3\0';

/**
 * Show on the device that SQLCipher encrypts the SDK database. SQLCipher
 * answers `PRAGMA cipher_version` on every connection, also on this one with
 * no key, so the version shows only that the app has the SQLCipher build. The
 * file header shows the encryption: a SQLCipher file starts with a random
 * salt, and a plaintext SQLite file starts with "SQLite format 3\0".
 */
async function checkEncryptionAtRest(unkeyed: SQLiteDatabase, log: (line: string) => void) {
  const row = await unkeyed.getFirstAsync<{ cipher_version?: string }>('PRAGMA cipher_version');
  const version = row?.cipher_version ?? '';
  log(`SQLCipher version: ${version || 'none'}`);

  const file = new File(`file://${defaultDatabaseDirectory}`, SDK_DATABASE_NAME);
  const header = (await file.bytes()).subarray(0, PLAINTEXT_HEADER.length);
  log(`SDK database header: ${Array.from(header, (byte) => byte.toString(16).padStart(2, '0')).join('') || 'empty'}`);

  if (!version) throw new Error('The SQLite build reports no SQLCipher version.');
  if (header.length < PLAINTEXT_HEADER.length || String.fromCharCode(...header) === PLAINTEXT_HEADER) {
    throw new Error('The SDK database file is not encrypted.');
  }
}

export function openAliceStore() {
  opened ??= openStore().catch((error) => { opened = undefined; throw error; });
  return opened;
}

async function openStore() {
  const store = await expoStore();
  // The example's run counters live in their own file. The SDK database
  // holds only SDK tables.
  const state = await openDatabaseAsync('opene2ee-example-state.db');
  await state.execAsync(`CREATE TABLE IF NOT EXISTS example_state (
    id integer PRIMARY KEY NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    completed integer DEFAULT 0 NOT NULL,
    identity_public text
  )`);

  return {
    store,
    async start(log: (line: string) => void) {
      log('Alice uses the SDK-owned device-local store.');
      await checkEncryptionAtRest(state, log);
      await state.runAsync('INSERT OR IGNORE INTO example_state (id, attempts, completed) VALUES (1, 0, 0)');
      const row = (await state.getFirstAsync<ExampleState>('SELECT * FROM example_state WHERE id = 1'))!;
      const identity = await store.getIdentityKey();
      if (row.identity_public && identity?.dhKey.publicKey !== row.identity_public) {
        throw new Error('The stored Alice identity did not match the previous run.');
      }
      if (row.identity_public) log(`Resumed Alice identity after ${row.completed} completed exchanges.`);
      else log('Create the first persistent Alice identity.');
      await state.runAsync('UPDATE example_state SET attempts = attempts + 1 WHERE id = 1');
      return row.attempts + 1;
    },
    async complete(log: (line: string) => void) {
      const identity = await store.getIdentityKey();
      if (!identity) throw new Error('Alice has no stored identity after the exchange.');
      await state.runAsync('UPDATE example_state SET completed = completed + 1, identity_public = ? WHERE id = 1', identity.dhKey.publicKey);
      log('Alice identity and session state remain in the device-local store. Close and reopen the app to check persistence.');
    },
  };
}
