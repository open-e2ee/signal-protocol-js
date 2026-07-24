/**
 * Node.js Storage Package
 *
 * Storage for Node.js applications using filesystem.
 */
export {};
import { NodeSignalStore, type NodeSignalStoreConfig } from './adapter';

export { NodeSignalStore } from './adapter';
export type { NodeSignalStoreConfig } from './adapter';

export async function nodeStore(config?: NodeSignalStoreConfig): Promise<NodeSignalStore> {
  const store = new NodeSignalStore(config);
  await store.initialize();
  return store;
}
