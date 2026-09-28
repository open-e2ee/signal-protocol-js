/**
 * React Native SQLite Signal Protocol Store Package
 *
 * Local Signal Protocol state in an SDK-owned SQLCipher database on op-sqlite.
 * The key of the database lives in a local secret vault, by default the
 * react-native-keychain vault.
 */
export {};

export {
  ReactNativeSignalProtocolStore,
  reactNativeStore,
  resetReactNativeStore,
  type ReactNativeSignalProtocolStoreOptions,
} from './adapter';
export { createPreKeyMaintenanceStore } from './maintenance';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, MessageRecordStore } from '../../../types';
