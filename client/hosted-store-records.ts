/**
 * The metadata keys of the hosted records in the application store.
 *
 * Each hosted record has two keys. The current key has the prefix
 * `signalRelay.<record>.v2:`. The earlier key has the `.v1:` prefix that SDK
 * 14.3.0 and earlier write. Each file that owns a record names its two
 * prefixes. The suffix after the prefix is the same in the two keys.
 *
 * This release writes only the current key. A read takes the current key
 * first and the earlier key second. When only the earlier key holds the
 * record, the read copies the record to the current key. The SDK never
 * deletes or replaces the earlier key to move a record, so a store that SDK
 * 14.3.0 or earlier wrote keeps each record under its earlier key. A delete
 * removes both keys. SDK 15 still reads the earlier key.
 *
 * SDK 14.2.0 and 14.3.0 read the current key first, so they read each record
 * that this release writes. SDK 14.1.0 and earlier read only the earlier key.
 * They do not find a record that this release created, and they read the
 * value that the earlier key held before this release changed the record.
 */
import type { SignalProtocolLocalStore } from '../types';

/** The two metadata key prefixes of one hosted record. */
export interface HostedStoreRecordPrefix {
  /** The `signalRelay.<record>.v2:` prefix. A read takes it first. */
  readonly current: string;
  /** The `.v1:` prefix that SDK 14.3.0 and earlier write. A read takes it second. */
  readonly earlier: string;
}

/** The two metadata keys of one hosted record. */
export type HostedStoreRecordKey = HostedStoreRecordPrefix;

type RecordReader = Pick<SignalProtocolLocalStore, 'getMetadata' | 'compareAndSetMetadata'>;
type RecordWriter = Pick<SignalProtocolLocalStore, 'setMetadata'>;
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
 *
 * When only the earlier key holds the record, the read copies it to the
 * current key and keeps the earlier key. The copy writes only an absent
 * current key. When a concurrent write fills the current key first, the read
 * returns that value.
 */
export async function readHostedStoreRecord(
  store: RecordReader,
  key: HostedStoreRecordKey,
): Promise<string | null> {
  const current = await store.getMetadata(key.current);
  if (current !== null) return current;
  const earlier = await store.getMetadata(key.earlier);
  if (earlier === null) return null;
  if (await store.compareAndSetMetadata(key.current, null, earlier)) return earlier;
  return store.getMetadata(key.current);
}

/** Stores a record under its current key. The earlier key keeps its value. */
export async function writeHostedStoreRecord(
  store: RecordWriter,
  key: HostedStoreRecordKey,
  value: string,
): Promise<void> {
  await store.setMetadata(key.current, value);
}

/** Deletes both keys of a record, so a read finds no earlier value. */
export async function deleteHostedStoreRecord(
  store: RecordRemover,
  key: HostedStoreRecordKey,
): Promise<void> {
  await store.deleteMetadata(key.current);
  await store.deleteMetadata(key.earlier);
}
