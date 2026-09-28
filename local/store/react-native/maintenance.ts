import type { PreKeyMaintenanceStore } from '../../../types/protocol-config';
import { createSqlitePreKeyMaintenanceStore } from '../sqlite/maintenance';
import {
  reactNativeStoreDatabase,
  type ReactNativeSignalProtocolStore,
} from './adapter';

/** Replaced-prekey maintenance on the database of an open store. */
export function createPreKeyMaintenanceStore(
  store: ReactNativeSignalProtocolStore
): PreKeyMaintenanceStore {
  return createSqlitePreKeyMaintenanceStore(reactNativeStoreDatabase(store));
}
