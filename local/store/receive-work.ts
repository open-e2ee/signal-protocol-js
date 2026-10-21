import type {
  ReceivedContent,
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  SignalProtocolLocalStore,
} from '../../types/api';
import { keyedGroupHash, keyedIndexSubkey } from './keyed-index';
import { parseReceivedContent, receivedContentKey } from './received-content';

/** The default page size of a receive-record listing. */
export const RECEIVE_WORK_DEFAULT_LIMIT = 100;

/** The metadata key that marks the legacy conversion as done. */
export const LEGACY_RECEIVED_CONTENT_MARKER_KEY = 'receive-work:legacy-conversion:v1';

/** The log code of a legacy row that does not parse. */
export const LEGACY_RECEIVED_CONTENT_UNREADABLE = 'LEGACY_RECEIVED_CONTENT_UNREADABLE';

const STAGES = new Set(['decrypted', 'receipt-due', 'awaiting-completion']);
const ORIGINS = new Set(['relay', 'caller']);
const MESSAGE_TYPES = new Set(['prekey_bundle', 'ciphertext', 'sender_key']);

/** The UTF-8 size of a receive record, without its `sizeBytes` field. */
export function receiveWorkSize(record: ReceiveWorkRecord): number {
  const { sizeBytes: _sizeBytes, ...rest } = record;
  return new TextEncoder().encode(JSON.stringify(rest)).length;
}

/** The record with its `sizeBytes` field set from its content. */
export function sizedReceiveWork(record: ReceiveWorkRecord): ReceiveWorkRecord {
  return { ...record, sizeBytes: receiveWorkSize(record) };
}

function isOptional(value: unknown, check: (value: unknown) => boolean): boolean {
  return value === undefined || check(value);
}

const isString = (value: unknown): boolean => typeof value === 'string';
const isNonEmptyString = (value: unknown): boolean => typeof value === 'string' && value !== '';
const isSafeInteger = (value: unknown): boolean => Number.isSafeInteger(value);
const isBoolean = (value: unknown): boolean => typeof value === 'boolean';

/**
 * Check the shape of one receive record. Throws on a record that a store
 * must not accept or return.
 */
export function assertReceiveWork(record: ReceiveWorkRecord, workId = record.workId): void {
  const candidate = record as unknown as Record<string, unknown>;
  const ackIntent = candidate.ackIntent as Record<string, unknown> | undefined;
  if (
    candidate === null ||
    typeof candidate !== 'object' ||
    !isNonEmptyString(candidate.workId) ||
    candidate.workId !== workId ||
    !isSafeInteger(candidate.revision) ||
    (candidate.revision as number) < 0 ||
    !STAGES.has(candidate.stage as string) ||
    !ORIGINS.has(candidate.origin as string) ||
    !isSafeInteger(candidate.arrivalSeq) ||
    !isSafeInteger(candidate.receivedAt) ||
    !isSafeInteger(candidate.dueAt) ||
    !isSafeInteger(candidate.sizeBytes) ||
    !isOptional(candidate.plaintext, isString) ||
    !isOptional(candidate.messageId, isNonEmptyString) ||
    !isOptional(candidate.envelopeId, isString) ||
    !isOptional(candidate.senderUserId, isNonEmptyString) ||
    !isOptional(candidate.senderDeviceId, isSafeInteger) ||
    !isOptional(candidate.messageType, (value) => MESSAGE_TYPES.has(value as string)) ||
    !isOptional(candidate.serverTimestamp, isSafeInteger) ||
    !isOptional(candidate.arrivedSealed, isBoolean) ||
    !isOptional(candidate.senderTimestamp, isSafeInteger) ||
    !isOptional(candidate.groupId, isNonEmptyString) ||
    !isOptional(candidate.blockedOn, (value) => value === 'group-update') ||
    !isOptional(
      ackIntent,
      () =>
        ackIntent !== null &&
        typeof ackIntent === 'object' &&
        isSafeInteger(ackIntent.at) &&
        isBoolean(ackIntent.hasReceiptJoin)
    ) ||
    !isOptional(candidate.relayOwnsReceipt, isBoolean) ||
    !isOptional(
      candidate.hookAttempts,
      (value) => isSafeInteger(value) && (value as number) > 0
    ) ||
    !isOptional(candidate.failedEnvelopeId, isNonEmptyString) ||
    !isOptional(candidate.awaitingEnvelope, (value) => value === true)
  ) {
    throw new Error('Invalid receive-work record');
  }
}

/** Parse one stored receive record. Throws on a value that is not one. */
export function parseReceiveWork(value: string, workId: string): ReceiveWorkRecord {
  const record = JSON.parse(value) as ReceiveWorkRecord;
  assertReceiveWork(record, workId);
  return record;
}

/** Tell whether one record matches a query, without the page limit. */
export function matchesReceiveWorkQuery(
  record: ReceiveWorkRecord,
  query: ReceiveWorkQuery = {}
): boolean {
  return (
    (query.stage === undefined || record.stage === query.stage) &&
    (query.dueBy === undefined || record.dueAt <= query.dueBy) &&
    isAfterReceiveWorkCursor(record.arrivalSeq, record.workId, query.after)
  );
}

/**
 * Tell whether a record sorts after a page cursor, in the order
 * `(arrivalSeq, workId)` of every store. An `arrivalSeq` is not unique, so
 * the cursor holds both values.
 */
function isAfterReceiveWorkCursor(
  arrivalSeq: number,
  workId: string,
  after: ReceiveWorkQuery['after']
): boolean {
  return (
    after === undefined ||
    arrivalSeq > after.arrivalSeq ||
    (arrivalSeq === after.arrivalSeq && compareStrings(workId, after.workId) > 0)
  );
}

/** Order, filter, and page a set of records, for a store that scans. */
export function selectReceiveWork(
  records: Iterable<ReceiveWorkRecord>,
  query: ReceiveWorkQuery = {}
): ReceiveWorkRecord[] {
  return [...records]
    .filter((record) => matchesReceiveWorkQuery(record, query))
    .sort((a, b) => a.arrivalSeq - b.arrivalSeq || compareStrings(a.workId, b.workId))
    .slice(0, receiveWorkLimit(query));
}

/** The page size of a query. */
export function receiveWorkLimit(query: ReceiveWorkQuery = {}): number {
  const limit = query.limit ?? RECEIVE_WORK_DEFAULT_LIMIT;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError('limit must be a positive integer');
  }
  return limit;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Tell whether a record counts toward the blocked usage of one group. */
export function isBlockedInGroup(record: ReceiveWorkRecord, groupId: string): boolean {
  return record.blockedOn === 'group-update' && record.groupId === groupId;
}

/**
 * The clear index fields of one record, for a store that encrypts the
 * record. A listing and a usage count read these fields, and they do not
 * decrypt a record to filter or count it.
 */
export interface ReceiveWorkIndex {
  revision: number;
  arrivalSeq: number;
  stage: ReceiveWorkRecord['stage'];
  dueAt: number;
  sizeBytes: number;
  /** The group key of a record that waits for its group. Absent on other records. */
  blockedGroup?: string;
}

/**
 * The group key of one group: an HMAC-SHA-256 of the group ID under a
 * subkey of the database key. A store keeps this key in the clear, and it
 * does not keep the raw group ID in the clear.
 */
export async function receiveWorkGroupKey(
  databaseKey: Uint8Array,
  groupId: string
): Promise<string> {
  return keyedGroupHash(await keyedIndexSubkey(databaseKey), groupId);
}

/** The clear index fields of one record, with the group key of a blocked record. */
export async function receiveWorkIndex(
  record: ReceiveWorkRecord,
  databaseKey: Uint8Array
): Promise<ReceiveWorkIndex> {
  const index: ReceiveWorkIndex = {
    revision: record.revision,
    arrivalSeq: record.arrivalSeq,
    stage: record.stage,
    dueAt: record.dueAt,
    sizeBytes: record.sizeBytes,
  };
  if (record.blockedOn === 'group-update' && record.groupId !== undefined) {
    index.blockedGroup = await receiveWorkGroupKey(databaseKey, record.groupId);
  }
  return index;
}

/** Tell whether the clear index fields of one record match a query, without the page limit. */
export function indexMatchesReceiveWorkQuery(
  index: ReceiveWorkIndex,
  workId: string,
  query: ReceiveWorkQuery = {}
): boolean {
  return (
    (query.stage === undefined || index.stage === query.stage) &&
    (query.dueBy === undefined || index.dueAt <= query.dueBy) &&
    isAfterReceiveWorkCursor(index.arrivalSeq, workId, query.after)
  );
}

/** The arrival order of a converted legacy row: before any new arrival. */
function legacyArrivalSeq(receivedAt: number): number {
  return receivedAt * 1024;
}

/** The receive record of one legacy row. */
export function legacyReceiveWork(content: ReceivedContent): ReceiveWorkRecord {
  return sizedReceiveWork({
    workId: content.id,
    revision: 0,
    stage: 'decrypted',
    origin: 'relay',
    arrivalSeq: legacyArrivalSeq(content.receivedAt),
    receivedAt: content.receivedAt,
    dueAt: content.receivedAt,
    sizeBytes: 0,
    plaintext: content.plaintext,
    ...(content.groupId !== undefined && { groupId: content.groupId }),
    awaitingEnvelope: true,
  });
}

/** The legacy rows of one store, as its adapter keeps them. */
export interface LegacyReceivedContentSource {
  /** The IDs of every legacy row. */
  listIds(): Promise<string[]>;
  /** The stored text of one legacy row, after any record cipher. Throws when unreadable. */
  read(id: string): Promise<string | null>;
  /** Delete one legacy row. */
  delete(id: string): Promise<void>;
}

/** The marker that the legacy conversion sets last. */
export interface LegacyConversionMarker {
  version: 1;
  /** The legacy keys of rows that did not parse. Each row stays in place. */
  unreadable: string[];
}

/**
 * Convert each legacy `ReceivedContent` row to a receive record with
 * `awaitingEnvelope: true`, at the first open after the upgrade.
 *
 * A row that parses becomes a record unless one exists for its ID, and
 * the row is deleted after its record commits. A row that does not parse
 * stays under its legacy key, and its key goes into the marker and the
 * error log. The marker is set last, so a crash reruns the conversion and
 * the rerun skips each row that has a record.
 *
 * The conversion takes no lock across processes, as the receive admission
 * in `client/receive-admission.ts` takes none. Two processes that open one
 * store at the same time, such as two browser tabs, can each convert one
 * row. When the first process completes its record before the second
 * process puts its own, the second record comes back, and the queue later
 * reports it as expired once. The window is a few store operations and one
 * decrypt, once after the upgrade.
 */
export async function convertLegacyReceivedContent(
  store: Pick<SignalProtocolLocalStore, 'getReceiveWork' | 'putReceiveWork' | 'getMetadata' | 'setMetadata'>,
  source: LegacyReceivedContentSource,
  reportUnreadable: (legacyKey: string) => void = (legacyKey) =>
    console.error(LEGACY_RECEIVED_CONTENT_UNREADABLE, legacyKey)
): Promise<void> {
  if ((await store.getMetadata(LEGACY_RECEIVED_CONTENT_MARKER_KEY)) !== null) return;
  const unreadable: string[] = [];
  for (const id of await source.listIds()) {
    let content: ReceivedContent;
    try {
      const value = await source.read(id);
      if (value === null) continue;
      content = parseReceivedContent(value, id);
    } catch {
      unreadable.push(receivedContentKey(id));
      reportUnreadable(receivedContentKey(id));
      continue;
    }
    if ((await store.getReceiveWork(id)) === null) {
      await store.putReceiveWork(legacyReceiveWork(content), null);
    }
    await source.delete(id);
  }
  const marker: LegacyConversionMarker = { version: 1, unreadable };
  await store.setMetadata(LEGACY_RECEIVED_CONTENT_MARKER_KEY, JSON.stringify(marker));
}
