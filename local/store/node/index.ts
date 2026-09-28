/**
 * Node and Electron Signal Protocol Store Package
 *
 * Local Signal Protocol state in an SDK-owned SQLCipher database on
 * better-sqlite3-multiple-ciphers. The key of the database lives in the app's
 * secret vault, for example the Electron safeStorage vault.
 */
export {};

export {
  NodeSignalProtocolStore,
  nodeStore,
  resetNodeStore,
  type NodeSignalProtocolStoreOptions,
} from './adapter';
export { createPreKeyMaintenanceStore } from './maintenance';
export { sqliteDatabaseKeySlot } from '../sqlite/open-store';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, MessageRecordStore } from '../../../types';
