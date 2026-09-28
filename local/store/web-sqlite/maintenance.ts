import type { PreKeyMaintenanceStore } from '../../../types/protocol-config';
import { createSqlitePreKeyMaintenanceStore } from '../sqlite/maintenance';
import { webSqliteStoreDatabase, type WebSqliteSignalProtocolStore } from './adapter';

/** Replaced-prekey maintenance on the database of an open store. */
export function createPreKeyMaintenanceStore(
  store: WebSqliteSignalProtocolStore
): PreKeyMaintenanceStore {
  return createSqlitePreKeyMaintenanceStore(webSqliteStoreDatabase(store));
}
