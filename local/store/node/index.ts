/**
 * Node.js Storage Package
 *
 * Storage for Node.js applications using filesystem.
 */
export {};
import { NodeSignalProtocolStore, type NodeSignalProtocolStoreConfig } from './adapter';

export { NodeSignalProtocolStore } from './adapter';
export type { NodeSignalProtocolStoreConfig } from './adapter';

export async function nodeStore(config?: NodeSignalProtocolStoreConfig): Promise<NodeSignalProtocolStore> {
  const store = new NodeSignalProtocolStore(config);
  await store.initialize();
  return store;
}
