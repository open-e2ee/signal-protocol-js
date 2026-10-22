/**
 * Conformance kit for a custom local store.
 *
 * An application that implements `SignalProtocolLocalStore` itself runs this
 * kit against its store. The kit checks the identity overwrite, the atomic
 * session trust and sender key commits and their rollback, metadata
 * compare-and-set, the receive records, durability after a reopen, the
 * stored bytes of a store that declares a cipher, and the protection
 * declaration. It does not check the sender key handoffs, the message
 * records, or the group send log.
 *
 * The kit has no framework or platform dependencies. It runs unchanged under
 * jest, Node, a browser, or Hermes.
 *
 * @example
 * ```typescript
 * import { assertLocalStoreConformance } from '@open-e2ee/signal-protocol-sdk/local/store/conformance';
 *
 * await assertLocalStoreConformance({
 *   createStore: () => openMyStore({ name: freshName() }),
 *   reopen: (store) => reopenMyStore(store),
 *   armWriteFailure: (store) => failNextReceiveRecordWrite(store),
 *   readRawBytes: (store) => readMyStoreFiles(store),
 *   closeStore: (store) => store.close(),
 * });
 * ```
 */

export { assertLocalStoreConformance, runLocalStoreConformance } from './run';
export type {
  LocalStoreConformanceFailure,
  LocalStoreConformanceOptions,
  LocalStoreConformanceResult,
} from './types';
