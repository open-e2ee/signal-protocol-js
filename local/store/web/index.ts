/**
 * Web Storage Package
 *
 * Experimental storage for web browsers using IndexedDB.
 * This adapter is not yet feature-equivalent with ExpoSignalStore.
 */
export {};
import { IndexedDbSignalStore } from './adapter';

export { IndexedDbSignalStore } from './adapter';

export async function indexedDbStore(): Promise<IndexedDbSignalStore> {
  const store = new IndexedDbSignalStore();
  await store.initialize();
  return store;
}
