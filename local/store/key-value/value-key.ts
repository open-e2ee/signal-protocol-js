/**
 * Custody of the key-value store's value key.
 *
 * The store encrypts each value with one 32-byte key. The key lives only in
 * the secret vault, never in the key-value backend beside the data it
 * encrypts. A backend that holds store data while the vault holds no key is a
 * lost key: opening reports it and changes nothing, because a new key cannot
 * read data encrypted under the lost one. Only an explicit reset deletes the
 * data and makes a new key.
 */

import { generateRandomBytes } from '../../../internal/crypto/random';
import type { SignalProtocolLocalSecretVault } from '../../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { KeyValueOperation, KeyValueStorage } from './storage';

/** The vault entry that holds the value key. */
const VALUE_KEY_SECRET_NAME = 'signal_key_value_encryption_key';

/** AES-256 value key size. */
const VALUE_KEY_SIZE = 32;

/** Every key the store writes to the backend starts with this prefix. */
const STORE_KEY_PREFIX = '@signal:';

async function readValueKey(vault: SignalProtocolLocalSecretVault): Promise<Uint8Array | null> {
  let key: Uint8Array | null;
  try {
    key = await vault.getSecret(VALUE_KEY_SECRET_NAME);
  } catch (error) {
    throw new EncryptionError(
      'Failed to read the value key from the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { originalError: error as Error }
    );
  }
  if (key && key.length !== VALUE_KEY_SIZE) {
    throw new EncryptionError(
      `The secret vault holds a value key of ${key.length} bytes; expected ${VALUE_KEY_SIZE}`,
      EncryptionErrorCode.KEY_STORAGE_ERROR
    );
  }
  return key;
}

/** Create a new value key and write it to the vault, over any old key. */
async function replaceValueKey(vault: SignalProtocolLocalSecretVault): Promise<Uint8Array> {
  const key = await generateRandomBytes(VALUE_KEY_SIZE);
  try {
    await vault.setSecret(VALUE_KEY_SECRET_NAME, key);
  } catch (error) {
    throw new EncryptionError(
      'Failed to write the value key to the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { originalError: error as Error }
    );
  }
  return key;
}

async function storeKeys(storage: KeyValueStorage): Promise<string[]> {
  const allKeys = await storage.getAllKeys();
  return allKeys.filter((key) => key.startsWith(STORE_KEY_PREFIX));
}

/**
 * Load the value key from the vault. Create it only when the backend holds
 * no store data.
 *
 * @throws EncryptionError with `LOCAL_STORE_KEY_LOST` when the backend holds
 *   store data and the vault holds no key.
 * @throws EncryptionError with `KEY_STORAGE_ERROR` when the vault fails or
 *   holds a key of the wrong size.
 */
export async function openValueKey(
  storage: KeyValueStorage,
  vault: SignalProtocolLocalSecretVault
): Promise<Uint8Array> {
  const storedKey = await readValueKey(vault);
  if (storedKey) return storedKey;

  if ((await storeKeys(storage)).length > 0) {
    throw new EncryptionError(
      'The key-value backend holds store data, but the secret vault holds no value key for it. ' +
        'Restore the vault entry, or call KeyValueSignalProtocolStore.reset(...) to delete the data.',
      EncryptionErrorCode.LOCAL_STORE_KEY_LOST
    );
  }

  return replaceValueKey(vault);
}

/**
 * Delete every store record, then create a new value key. Entries outside the
 * store's prefix stay.
 *
 * The order is the crash contract. The deletion is one `atomicWrite`, so it
 * commits all or nothing. A process that stops after it and before the vault
 * write leaves no store data and the old key or none, and
 * {@link openValueKey} opens that state as an empty store. The other order
 * would leave data under a key that no longer exists.
 */
export async function deleteDataThenReplaceValueKey(
  storage: KeyValueStorage,
  vault: SignalProtocolLocalSecretVault
): Promise<Uint8Array> {
  const keys = await storeKeys(storage);
  if (keys.length > 0) {
    await storage.atomicWrite(
      keys.map((key): KeyValueOperation => ({ type: 'remove', key }))
    );
  }
  return replaceValueKey(vault);
}
