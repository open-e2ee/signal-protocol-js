/**
 * Web Storage Package
 *
 * Experimental storage for web browsers using IndexedDB.
 * This adapter is not yet feature-equivalent with ExpoSignalProtocolStore.
 */
export {};
import { IndexedDbSignalProtocolStore } from './adapter';

export { IndexedDbSignalProtocolStore } from './adapter';

export async function indexedDbStore(): Promise<IndexedDbSignalProtocolStore> {
  const store = new IndexedDbSignalProtocolStore();
  await store.initialize();
  return store;
}
