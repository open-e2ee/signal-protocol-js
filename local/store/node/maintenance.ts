import type { PreKeyMaintenanceStore } from '../../../types/protocol-config';
import { createSqlitePreKeyMaintenanceStore } from '../sqlite/maintenance';
import { nodeStoreDatabase, type NodeSignalProtocolStore } from './adapter';

/** Replaced-prekey maintenance on the database of an open store. */
export function createPreKeyMaintenanceStore(
  store: NodeSignalProtocolStore
): PreKeyMaintenanceStore {
  return createSqlitePreKeyMaintenanceStore(nodeStoreDatabase(store));
}
