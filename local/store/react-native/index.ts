/**
 * React Native Storage Package (Bare Workflow)
 *
 * Experimental storage for React Native without Expo.
 * Consumers must provide their own persistent key-value backend and construct
 * the store with `await ReactNativeSignalProtocolStore.create({ storage })`.
 * The adapter implements the core store contract, but its durability and
 * platform-hardening depend on the injected backend.
 */
export {};
import { ReactNativeSignalProtocolStore } from './adapter';
import type { ReactNativeKeyValueStorage } from './storage';

export { ReactNativeSignalProtocolStore } from './adapter';
export type { ReactNativeKeyValueStorage } from './storage';

export interface ReactNativeStoreFactoryOptions {
  storage: ReactNativeKeyValueStorage;
}

export function reactNativeStore(
  options: ReactNativeStoreFactoryOptions
): Promise<ReactNativeSignalProtocolStore> {
  return ReactNativeSignalProtocolStore.create(options);
}
