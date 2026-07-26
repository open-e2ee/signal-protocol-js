import * as SecureStore from 'expo-secure-store';

/**
 * SecureStore accessibility used by SDK-managed background-safe secrets.
 *
 * Signal Protocol keys and device metadata must be readable after first unlock so
 * background delivery and recovery flows can function while the device is locked.
 */
export {};
export const SIGNAL_PROTOCOL_SECURE_STORE_OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
};
