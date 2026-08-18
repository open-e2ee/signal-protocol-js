/**
 * Web Storage Package
 *
 * Storage for web browsers using IndexedDB. Implements the full core
 * store contract. See local/store/web/README.md for the security
 * boundary and the gates that verify it.
 */
export {};
import { IndexedDbSignalProtocolStore } from './adapter';

export { IndexedDbSignalProtocolStore } from './adapter';

export async function indexedDbStore(): Promise<IndexedDbSignalProtocolStore> {
  const store = new IndexedDbSignalProtocolStore();
  await store.initialize();
  return store;
}
