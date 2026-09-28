import type { PreKeyMaintenanceStore } from '../../../types/protocol-config';
import { createSqlitePreKeyMaintenanceStore } from '../sqlite/maintenance';
import { expoStoreDatabase, type ExpoSignalProtocolStore } from './adapter';

/** Replaced-prekey maintenance on the database of an open store. */
export function createPreKeyMaintenanceStore(store: ExpoSignalProtocolStore): PreKeyMaintenanceStore {
  return createSqlitePreKeyMaintenanceStore(expoStoreDatabase(store));
}
