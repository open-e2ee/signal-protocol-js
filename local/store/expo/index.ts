/**
 * Expo Signal Protocol Store Package
 *
 * Local Signal Protocol state in an SDK-owned SQLCipher database. The key of
 * the database lives in a local secret vault, by default Expo SecureStore.
 */
export {};

export {
  ExpoSignalProtocolStore,
  expoStore,
  resetExpoStore,
  type ExpoSignalProtocolStoreOptions,
} from './adapter';
export { createPreKeyMaintenanceStore } from './maintenance';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, MessageRecordStore } from '../../../types';
