/**
 * The metadata keys of the hosted records in the application store.
 *
 * Each hosted record has two keys. The current key has the prefix
 * `signalRelay.<record>.v2:`. The earlier key has the `.v1:` prefix that SDK
 * 14.1.0 and earlier read and write. Each file that owns a record names its
 * two prefixes. The suffix after the prefix is the same in the two keys.
 *
 * In this release a read takes the current key first and the earlier key
 * second, and a write keeps the earlier key. So a store that SDK 14.1.0 wrote
 * opens with its records, and a return to SDK 14.1.0 still finds every
 * record. A later release writes the current key. A write also updates a
 * current key that the store holds, so the current key, which a read prefers,
 * never keeps a value that a later write replaced. SDK 15 still reads the
 * earlier key.
 */
import type { SignalProtocolLocalStore } from '../types';

/** The two metadata key prefixes of one hosted record. */
export interface HostedStoreRecordPrefix {
  /** The `signalRelay.<record>.v2:` prefix. A read takes it first. */
  readonly current: string;
  /** The `.v1:` prefix that SDK 14.1.0 writes. A read takes it second. */
  readonly earlier: string;
}

/** The two metadata keys of one hosted record. */
export type HostedStoreRecordKey = HostedStoreRecordPrefix;

type RecordReader = Pick<SignalProtocolLocalStore, 'getMetadata'>;
type RecordWriter = Pick<SignalProtocolLocalStore, 'getMetadata' | 'setMetadata'>;
type RecordRemover = Pick<SignalProtocolLocalStore, 'deleteMetadata'>;

/** The keys of the record that `suffix` names under `prefix`. */
export function hostedStoreRecordKey(
  prefix: HostedStoreRecordPrefix,
  suffix: string,
): HostedStoreRecordKey {
  return {
    current: `${prefix.current}${suffix}`,
    earlier: `${prefix.earlier}${suffix}`,
  };
}

/**
 * The stored value of a record, or `null` when neither key holds one. The
 * current key wins when the store holds both keys.
 */
export async function readHostedStoreRecord(
  store: RecordReader,
  key: HostedStoreRecordKey,
): Promise<string | null> {
  const current = await store.getMetadata(key.current);
  return current !== null ? current : store.getMetadata(key.earlier);
}

/**
 * Stores a record under its earlier key. It first replaces a current key that
 * the store holds, so that a failure between the two writes leaves the newer
 * value under the key that a read prefers.
 */
export async function writeHostedStoreRecord(
  store: RecordWriter,
  key: HostedStoreRecordKey,
  value: string,
): Promise<void> {
  if ((await store.getMetadata(key.current)) !== null) {
    await store.setMetadata(key.current, value);
  }
  await store.setMetadata(key.earlier, value);
}

/** Deletes both keys of a record, so a read finds no earlier value. */
export async function deleteHostedStoreRecord(
  store: RecordRemover,
  key: HostedStoreRecordKey,
): Promise<void> {
  await store.deleteMetadata(key.current);
  await store.deleteMetadata(key.earlier);
}
