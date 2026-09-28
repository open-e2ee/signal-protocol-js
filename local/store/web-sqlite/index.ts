/**
 * Web SQLite Signal Protocol Store Package
 *
 * Local Signal Protocol state in an SDK-owned SQLite database in the origin
 * private file system, encrypted by SQLite3 Multiple Ciphers in a Wasm
 * worker. The key of the database lives in a local secret vault, by default
 * IndexedDB in the same origin. See local/store/web-sqlite/README.md for the
 * Content Security Policy and the security boundary.
 */
export {};

export {
  WebSqliteSignalProtocolStore,
  webSqliteStore,
  resetWebSqliteStore,
  type WebSqliteSignalProtocolStoreOptions,
} from './adapter';
export { createPreKeyMaintenanceStore } from './maintenance';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, MessageRecordStore } from '../../../types';
