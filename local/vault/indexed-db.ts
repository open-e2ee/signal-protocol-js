import { openDB, type DBSchema, type IDBPDatabase } from 'idb';

import type { SecretVaultCustody, SignalProtocolLocalSecretVault } from '../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../types/errors';

const DEFAULT_DATABASE_NAME = 'open-e2ee-secret-vault';
const STORE_NAME = 'secrets';

interface SecretVaultSchema extends DBSchema {
  secrets: {
    key: string;
    value: Uint8Array;
  };
}

export interface IndexedDbSignalProtocolSecretVaultOptions {
  /** The IndexedDB database that holds the secrets. */
  readonly databaseName?: string;
}

function keyStorageError(message: string, operation: string, cause?: unknown): EncryptionError {
  return new EncryptionError(message, EncryptionErrorCode.KEY_STORAGE_ERROR, {
    operation,
    ...(cause instanceof Error ? { originalError: cause } : {}),
  });
}

function detail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function assertName(name: string, operation: string): void {
  if (name.length === 0) {
    throw keyStorageError('IndexedDB secret name must not be empty', operation);
  }
}

/** Checks the tag, because a value can come from another realm. */
function isNonEmptyBytes(value: unknown): value is Uint8Array {
  return (
    Object.prototype.toString.call(value) === '[object Uint8Array]' &&
    (value as Uint8Array).length > 0
  );
}

/**
 * IndexedDB-backed local secret vault for the web.
 *
 * The vault stores each secret as raw bytes in one IndexedDB object store,
 * under the secret name.
 *
 * This vault is not a secret manager. The secret is raw bytes in IndexedDB in
 * the same origin as the encrypted database: the documented exception to
 * "the key never sits beside the data".
 *
 * - What the key protects: a copy of the database file that does not also
 *   include this IndexedDB record.
 * - What it does not protect: script that runs in the origin (XSS), a
 *   browser extension with access to the site, malware that reads the
 *   browser profile, or a copy of the full profile. It is not an XSS
 *   defense.
 *
 * An app with a different custody supplies its own vault.
 */
export class IndexedDbSignalProtocolSecretVault implements SignalProtocolLocalSecretVault {
  /** The key sits in the same origin as the data that it protects. */
  readonly custody: SecretVaultCustody = 'same-origin';

  private readonly databaseName: string;

  constructor(options: IndexedDbSignalProtocolSecretVaultOptions = {}) {
    this.databaseName = options.databaseName ?? DEFAULT_DATABASE_NAME;
  }

  async getSecret(name: string): Promise<Uint8Array | null> {
    assertName(name, 'getSecret');
    const stored: unknown = await this.request('getSecret', (database) => database.get(STORE_NAME, name));
    if (stored === undefined) return null;
    if (!isNonEmptyBytes(stored)) {
      throw keyStorageError('IndexedDB secret is not a non-empty byte array', 'getSecret');
    }
    return stored;
  }

  async setSecret(name: string, value: Uint8Array): Promise<void> {
    assertName(name, 'setSecret');
    if (!isNonEmptyBytes(value)) {
      throw keyStorageError('IndexedDB secret value must be a non-empty byte array', 'setSecret');
    }
    await this.request('setSecret', (database) => database.put(STORE_NAME, value, name));
  }

  async deleteSecret(name: string): Promise<void> {
    assertName(name, 'deleteSecret');
    await this.request('deleteSecret', (database) => database.delete(STORE_NAME, name));
  }

  /**
   * Runs one request on its own connection, and reports its failure as
   * `KEY_STORAGE_ERROR`. The connection closes when the request settles. So
   * the vault holds no connection between requests, and a page that opens a
   * store many times keeps no connection for each open.
   */
  private async request<T>(
    operation: string,
    run: (database: IDBPDatabase<SecretVaultSchema>) => Promise<T>
  ): Promise<T> {
    const database = await this.open();
    try {
      return await run(database);
    } catch (error) {
      throw keyStorageError(`IndexedDB secret vault ${operation} failed: ${detail(error)}`, operation, error);
    } finally {
      database.close();
    }
  }

  /** Opens a connection for one request. */
  private async open(): Promise<IDBPDatabase<SecretVaultSchema>> {
    try {
      return await openDB<SecretVaultSchema>(this.databaseName, 1, {
        upgrade(database) {
          database.createObjectStore(STORE_NAME);
        },
        // Another context deletes or upgrades the database during a request:
        // let it proceed.
        blocking: (_currentVersion, _blockedVersion, event) => {
          (event.target as IDBDatabase).close();
        },
      });
    } catch (error) {
      throw keyStorageError(`IndexedDB secret vault did not open: ${detail(error)}`, 'open', error);
    }
  }
}
