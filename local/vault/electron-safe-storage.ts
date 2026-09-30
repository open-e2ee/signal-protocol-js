import { open, readFile, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { SignalProtocolLocalSecretVault } from '../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../types/errors';
import { asBase64 } from '../../types/utils';
import { base64ToBytes, bytesToBase64 } from '../../encoding';
import { bytesToHex, hexToBytes } from '../../encoding/hex';

const STORED_HEX = /^(?:[0-9a-f]{2})+$/;
const STORED_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** The ASCII prefix of a Linux ciphertext under a key from the secret service. */
const SECRET_SERVICE_PREFIX = [0x76, 0x31, 0x31];
/** The ASCII prefix of a Linux ciphertext under the key of the Secret portal. */
const SECRET_PORTAL_PREFIX = [0x76, 0x31, 0x32];

function hasPrefix(ciphertext: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((byte, index) => ciphertext[index] === byte);
}

/**
 * The part of Electron's `safeStorage` that the vault uses. The app passes
 * `safeStorage` from `electron`, so the SDK never imports `electron`.
 */
export interface ElectronSafeStorage {
  isAsyncEncryptionAvailable(): Promise<boolean>;
  encryptStringAsync(plainText: string): Promise<Uint8Array>;
  decryptStringAsync(
    encrypted: Uint8Array
  ): Promise<{ shouldReEncrypt: boolean; result: string }>;
  /** Present on Linux only. */
  getSelectedStorageBackend?(): string;
}

export interface ElectronSafeStorageSecretVaultOptions {
  /** `safeStorage` from `electron`, in the main process. */
  safeStorage: ElectronSafeStorage;
  /**
   * The file that holds the ciphertexts, for example under
   * `app.getPath('userData')`. Its directory must exist. One vault owns it.
   */
  file: string;
}

function keyStorageError(message: string, operation: string, cause?: unknown): EncryptionError {
  return new EncryptionError(message, EncryptionErrorCode.KEY_STORAGE_ERROR, {
    operation,
    ...(cause instanceof Error ? { originalError: cause } : {}),
  });
}

function assertName(name: string, operation: string): void {
  if (name.length === 0) {
    throw keyStorageError('Electron safeStorage secret name must not be empty', operation);
  }
}

function parseSecrets(text: string): Map<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw keyStorageError('Electron safeStorage vault file is not a JSON object', 'read');
  }
  const secrets = new Map<string, string>();
  for (const [name, value] of Object.entries(parsed)) {
    if (typeof value !== 'string' || value.length === 0 || !STORED_BASE64.test(value)) {
      throw keyStorageError('Electron safeStorage vault file holds a value that is not base64', 'read');
    }
    secrets.set(name, value);
  }
  return secrets;
}

/**
 * Electron `safeStorage`-backed local secret vault for the Electron main
 * process. `safeStorage` encrypts each secret, as lowercase hex, under a key
 * that the OS holds: the macOS Keychain, Windows DPAPI, or the Linux secret
 * store. The vault keeps only the ciphertexts, as base64 in a JSON file that
 * the app names, so no secret is on disk in plaintext.
 *
 * Use the vault after the app is ready. It fails closed when async encryption
 * is not available, and on Linux when the backend is `basic_text` or
 * `unknown`, or when a ciphertext does not start with `v11`. On macOS, sign
 * every build with the same identity: a build with a different signature can
 * make the Keychain ask the user again.
 */
export class ElectronSafeStorageSignalProtocolSecretVault
  implements SignalProtocolLocalSecretVault
{
  readonly #safeStorage: ElectronSafeStorage;
  readonly #file: string;
  #queue: Promise<unknown> = Promise.resolve();

  constructor({ safeStorage, file }: ElectronSafeStorageSecretVaultOptions) {
    this.#safeStorage = safeStorage;
    this.#file = file;
  }

  async getSecret(name: string): Promise<Uint8Array | null> {
    assertName(name, 'getSecret');
    return this.#serialize(async () => {
      const secrets = await this.#read();
      const stored = secrets.get(name);
      if (stored === undefined) return null;
      await this.#assertProtected('getSecret');
      const ciphertext = base64ToBytes(asBase64(stored));
      this.#assertSecretServiceKey(ciphertext, 'getSecret');
      let decrypted: { shouldReEncrypt: boolean; result: string };
      try {
        decrypted = await this.#safeStorage.decryptStringAsync(ciphertext);
      } catch (error) {
        throw keyStorageError('Electron safeStorage could not decrypt the secret', 'getSecret', error);
      }
      if (!STORED_HEX.test(decrypted.result)) {
        throw keyStorageError(
          'Electron safeStorage secret is not a lowercase hex byte string',
          'getSecret'
        );
      }
      if (decrypted.shouldReEncrypt) {
        secrets.set(name, await this.#encrypt(decrypted.result, 'getSecret'));
        await this.#write(secrets);
      }
      return hexToBytes(decrypted.result);
    });
  }

  async setSecret(name: string, value: Uint8Array): Promise<void> {
    assertName(name, 'setSecret');
    if (value.length === 0) {
      throw keyStorageError('Electron safeStorage secret value must not be empty', 'setSecret');
    }
    const hex = bytesToHex(value);
    await this.#serialize(async () => {
      await this.#assertProtected('setSecret');
      const secrets = await this.#read();
      secrets.set(name, await this.#encrypt(hex, 'setSecret'));
      await this.#write(secrets);
    });
  }

  async deleteSecret(name: string): Promise<void> {
    assertName(name, 'deleteSecret');
    await this.#serialize(async () => {
      const secrets = await this.#read();
      if (secrets.delete(name)) await this.#write(secrets);
    });
  }

  /**
   * Each operation reads, changes, and writes the whole file, so the vault
   * runs one at a time. A failed operation does not stop the next one.
   */
  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#queue.then(operation);
    this.#queue = result.catch(() => undefined);
    return result;
  }

  /**
   * Before the app is ready, encryption is not available and the Linux backend
   * is `unknown`. `basic_text` encrypts with a fixed password, so it does not
   * protect the secret. A `gnome_libsecret` or `kwallet` backend can also use a
   * fixed key, so `#assertSecretServiceKey` checks each Linux ciphertext.
   */
  async #assertProtected(operation: string): Promise<void> {
    if (!(await this.#safeStorage.isAsyncEncryptionAvailable())) {
      throw keyStorageError(
        'Electron safeStorage encryption is not available. Use the vault in the main process after the app is ready.',
        operation
      );
    }
    const backend = this.#safeStorage.getSelectedStorageBackend?.();
    if (backend === undefined) {
      if (process.platform !== 'linux') return;
      throw keyStorageError(
        'Electron safeStorage does not report its Linux storage backend. Pass safeStorage from electron.',
        operation
      );
    }
    if (backend === 'basic_text') {
      throw keyStorageError(
        'Electron safeStorage uses the basic_text backend, which encrypts with a fixed password. Run the app with a secret store such as gnome-libsecret or kwallet.',
        operation
      );
    }
    if (backend === 'unknown') {
      throw keyStorageError(
        'Electron safeStorage has no storage backend. Use the vault in the main process after the app is ready.',
        operation
      );
    }
  }

  /**
   * On Linux, safeStorage uses its fixed fallback key when no secret service
   * answers, and the backend does not show it. The ciphertext prefix names the
   * key: `v11` is a key from the secret service, and `v10` is the fallback key.
   * `v12` is the key of the Secret portal, which safeStorage uses only with the
   * `SecretPortalKeyProviderUseForEncryption` feature. Outside a Flatpak or
   * Snap sandbox, Chromium asks the portal for that key as the app
   * `org.chromium.Chromium`, so every such Electron app of the user gets the
   * same key. Any other prefix is a key that the vault does not know. The vault
   * fails closed on each key other than `v11`.
   */
  #assertSecretServiceKey(ciphertext: Uint8Array, operation: string): void {
    if (process.platform !== 'linux') return;
    if (hasPrefix(ciphertext, SECRET_SERVICE_PREFIX)) return;
    if (hasPrefix(ciphertext, SECRET_PORTAL_PREFIX)) {
      throw keyStorageError(
        'Electron safeStorage encrypted with the key of the Secret portal. Outside a Flatpak or Snap sandbox, the portal gives that key to Electron as the Chromium app, so other Electron apps of the user get the same key. Run the app without the SecretPortalKeyProviderUseForEncryption feature.',
        operation
      );
    }
    throw keyStorageError(
      'Electron safeStorage did not encrypt with a key from a secret service. When no secret service answers, safeStorage uses its fixed fallback key. Run the app with a secret service such as gnome-keyring or kwallet.',
      operation
    );
  }

  async #encrypt(hex: string, operation: string): Promise<string> {
    let encrypted: Uint8Array;
    try {
      encrypted = await this.#safeStorage.encryptStringAsync(hex);
    } catch (error) {
      throw keyStorageError('Electron safeStorage could not encrypt the secret', operation, error);
    }
    if (encrypted.length === 0) {
      throw keyStorageError('Electron safeStorage returned an empty ciphertext', operation);
    }
    this.#assertSecretServiceKey(encrypted, operation);
    return bytesToBase64(encrypted);
  }

  async #read(): Promise<Map<string, string>> {
    let text: string;
    try {
      text = await readFile(this.#file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Map();
      throw error;
    }
    return parseSecrets(text);
  }

  /**
   * Replace the file atomically: write and sync a temporary file, rename it
   * over the old one, then sync the directory so that the rename survives a
   * power loss. Windows cannot open a directory to sync it.
   */
  async #write(secrets: Map<string, string>): Promise<void> {
    const temporary = `${this.#file}.tmp`;
    const handle = await open(temporary, 'w', 0o600);
    try {
      await handle.writeFile(JSON.stringify(Object.fromEntries(secrets)), 'utf8');
      await handle.sync();
    } catch (error) {
      await handle.close();
      await rm(temporary, { force: true });
      throw error;
    }
    await handle.close();
    await rename(temporary, this.#file);
    if (process.platform === 'win32') return;
    const directory = await open(dirname(this.#file), 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}
