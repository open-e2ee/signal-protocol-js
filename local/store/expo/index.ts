/**
 * Expo Signal Protocol Store Package
 *
 * Encrypted local-store implementation for Signal Protocol state.
 * Uses SQLCipher for full-database encryption with a separate local secret vault.
 */
export {};
import { ExpoSignalProtocolStore } from './adapter';
import type { ILogger } from '../../../logger';

export { ExpoSignalProtocolStore } from './adapter';
export { getKeyStorage, resetKeyStorage } from './key-storage';
export {
  getDatabaseKeyManager,
  resetDatabaseKeyManager,
  clearDatabaseKeyCache,
} from './database-key';
export { getPrimaryIdentityKey, getContactIdentity } from './models';
export { createPreKeyMaintenanceStore } from './maintenance';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, IMessageRecordStore } from '../../../types';

export interface ExpoSignalProtocolStoreFactoryOptions {
  logger?: ILogger;
}

export function expoStore(
  options: ExpoSignalProtocolStoreFactoryOptions = {}
): ExpoSignalProtocolStore {
  return new ExpoSignalProtocolStore(options.logger);
}
