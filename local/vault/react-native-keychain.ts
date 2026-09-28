import {
  ACCESSIBLE,
  SECURITY_LEVEL,
  STORAGE_TYPE,
  getGenericPassword,
  resetGenericPassword,
  setGenericPassword,
  type BaseOptions,
  type SetOptions,
} from 'react-native-keychain';
import type { SignalProtocolLocalSecretVault } from '../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../types/errors';
import { bytesToHex, hexToBytes } from '../../encoding/hex';

const STORED_HEX = /^(?:[0-9a-f]{2})+$/;

/**
 * Options for every write. The app cannot change them.
 *
 * - `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` keeps the iOS item out of backups
 *   and off other devices, and lets a background task read it after the
 *   first unlock.
 * - `AES_GCM_NO_AUTH` keeps the Android key in the Keystore with no
 *   biometric prompt.
 * - `SECURE_SOFTWARE` requires that Android key to be in the Keystore, apart
 *   from the data. `SECURE_HARDWARE` fails on emulators and on software
 *   keymasters, and the library checks it only when it generates a new key.
 *   `ANY` removes the Keystore check.
 *
 * `cloudSync` is never set. On iOS, react-native-keychain 10.0.0 turns iCloud
 * sync on for any value of that key, `false` included (issue #800).
 *
 * The library adds `authenticationPrompt` to the object it receives, so each
 * call gets a new object.
 */
function writeOptions(name: string): SetOptions {
  return {
    service: name,
    accessible: ACCESSIBLE.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    storage: STORAGE_TYPE.AES_GCM_NO_AUTH,
    securityLevel: SECURITY_LEVEL.SECURE_SOFTWARE,
  };
}

function lookupOptions(name: string): BaseOptions {
  return { service: name };
}

function assertName(name: string, operation: string): void {
  if (name.length === 0) {
    throw new EncryptionError(
      'Keychain secret name must not be empty',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation }
    );
  }
}

/**
 * react-native-keychain-backed local secret vault for tiny bootstrap secrets
 * in a bare React Native app. The secret name is the keychain service, and the
 * value is stored as lowercase hex.
 */
export class ReactNativeKeychainSignalProtocolSecretVault
  implements SignalProtocolLocalSecretVault
{
  async getSecret(name: string): Promise<Uint8Array | null> {
    assertName(name, 'getSecret');
    const credentials = await getGenericPassword(lookupOptions(name));
    if (!credentials) return null;
    if (!STORED_HEX.test(credentials.password)) {
      throw new EncryptionError(
        'Keychain secret is not a lowercase hex byte string',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { operation: 'getSecret' }
      );
    }
    return hexToBytes(credentials.password);
  }

  async setSecret(name: string, value: Uint8Array): Promise<void> {
    assertName(name, 'setSecret');
    if (value.length === 0) {
      throw new EncryptionError(
        'Keychain secret value must not be empty',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { operation: 'setSecret' }
      );
    }
    const result = await setGenericPassword(name, bytesToHex(value), writeOptions(name));
    if (result === false) {
      throw new EncryptionError(
        'Keychain did not store the secret',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { operation: 'setSecret' }
      );
    }
  }

  async deleteSecret(name: string): Promise<void> {
    assertName(name, 'deleteSecret');
    await resetGenericPassword(lookupOptions(name));
  }
}
