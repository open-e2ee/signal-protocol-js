import * as SecureStore from 'expo-secure-store';

import type { ISignalLocalSecretVault } from '../../types/api';
import { base64ToBytes, bytesToBase64 } from '../../encoding';
import { asBase64 } from '../../types/utils';
import { SIGNAL_SECURE_STORE_OPTIONS } from '../store/expo/secure-store-options';

/**
 * Expo SecureStore-backed local secret vault for tiny bootstrap secrets.
 */
export class ExpoSecureStoreSignalSecretVault implements ISignalLocalSecretVault {
  async getSecret(name: string): Promise<Uint8Array | null> {
    const stored = await SecureStore.getItemAsync(name, SIGNAL_SECURE_STORE_OPTIONS);
    if (!stored) {
      return null;
    }

    return base64ToBytes(asBase64(stored));
  }

  async setSecret(name: string, value: Uint8Array): Promise<void> {
    await SecureStore.setItemAsync(name, bytesToBase64(value), SIGNAL_SECURE_STORE_OPTIONS);
  }

  async deleteSecret(name: string): Promise<void> {
    await SecureStore.deleteItemAsync(name, SIGNAL_SECURE_STORE_OPTIONS);
  }
}
