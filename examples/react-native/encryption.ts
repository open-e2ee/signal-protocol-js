import { ANDROID_DATABASE_PATH, IOS_LIBRARY_PATH, open, type DB } from '@op-engineering/op-sqlite';
import { EncryptionError, EncryptionErrorCode, type SignalProtocolLocalSecretVault } from '@open-e2ee/signal-protocol-sdk';
import { reactNativeStore, resetReactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';
import { Platform } from 'react-native';

// The file that reactNativeStore() opens when the options name none.
const SDK_DATABASE_NAME = 'open-e2ee-signal-protocol.db';
const PLAINTEXT_HEADER = 'SQLite format 3\0';
const WRONG_KEY_DATABASE_NAME = 'opene2ee-wrong-key-check.db';

/**
 * Show on the device that SQLCipher encrypts the SDK database. SQLCipher
 * answers `PRAGMA cipher_version` on every connection, also on this one with
 * no key, so the version shows only that the app has the SQLCipher build. The
 * file header shows the encryption: a SQLCipher file starts with a random
 * salt, and a plaintext SQLite file starts with "SQLite format 3\0".
 */
export async function checkEncryptionAtRest(unkeyed: DB, log: (line: string) => void) {
  const row = unkeyed.executeSync('PRAGMA cipher_version').rows[0];
  const version = typeof row?.cipher_version === 'string' ? row.cipher_version : '';
  log(`SQLCipher version: ${version || 'none'}`);

  // op-sqlite keeps its files in the Library directory on iOS and in the
  // databases directory on Android. React Native fetch reads a file URL.
  const directory = (Platform.OS === 'ios' ? IOS_LIBRARY_PATH : ANDROID_DATABASE_PATH).replace(/\/$/, '');
  const file = await fetch(`file://${directory}/${SDK_DATABASE_NAME}`);
  const header = new Uint8Array(await file.arrayBuffer()).subarray(0, PLAINTEXT_HEADER.length);
  log(`SDK database header: ${Array.from(header, (byte) => byte.toString(16).padStart(2, '0')).join('') || 'empty'}`);

  if (!version) throw new Error('The SQLite build reports no SQLCipher version.');
  if (header.length < PLAINTEXT_HEADER.length || String.fromCharCode(...header) === PLAINTEXT_HEADER) {
    throw new Error('The SDK database file is not encrypted.');
  }
}

/**
 * Show that a wrong key does not open an SDK database. The check creates a
 * separate database with a key in memory, closes it, inverts each bit of the
 * key, and requires the next open to fail. It deletes the files at the end.
 */
export async function checkWrongKey(log: (line: string) => void) {
  const secrets = new Map<string, Uint8Array>();
  const vault: SignalProtocolLocalSecretVault = {
    getSecret: async (name) => secrets.get(name) ?? null,
    setSecret: async (name, value) => { secrets.set(name, value); },
    deleteSecret: async (name) => { secrets.delete(name); },
  };
  const options = { name: WRONG_KEY_DATABASE_NAME, vault };
  await (await resetReactNativeStore(options)).close();
  for (const [name, key] of secrets) secrets.set(name, key.map((byte) => byte ^ 0xff));

  let failure: unknown;
  try {
    await (await reactNativeStore(options)).close();
  } catch (error) {
    failure = error;
  } finally {
    removeDatabase(WRONG_KEY_DATABASE_NAME);
  }
  // The store reports a key that does not read the file as SqliteKeyMismatchError.
  if (
    !(failure instanceof EncryptionError) ||
    failure.name !== 'SqliteKeyMismatchError' ||
    failure.code !== EncryptionErrorCode.KEY_STORAGE_ERROR
  ) {
    throw new Error(`A wrong key opened the SDK database, or the open failed another way: ${String(failure)}`);
  }
  log(`Wrong key: the open failed with ${failure.name} (${failure.code}).`);
}

/**
 * op-sqlite `delete` removes only the named file, so this also removes the WAL
 * files. `failOnCreate` makes the open of a file that does not exist throw.
 */
function removeDatabase(name: string) {
  for (const file of [`${name}-wal`, `${name}-shm`, name]) {
    let database: DB;
    try {
      database = open({ name: file, failOnCreate: true });
    } catch {
      continue;
    }
    database.delete();
  }
}
