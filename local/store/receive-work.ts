import type { Logger } from '../../logger';
import type {
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  SignalProtocolLocalStore,
} from '../../types/api';
import { readRenamedOption, type RenamedMember } from '../../types/renamed-member';
import { keyedGroupHash, keyedIndexSubkey } from './keyed-index';

/** The default page size of a receive-record listing. */
export const RECEIVE_WORK_DEFAULT_LIMIT = 100;

/**
 * The metadata key that the legacy conversion of SDK 13.x set when it was
 * done. The sweep deletes it.
 */
export const LEGACY_RECEIVED_CONTENT_MARKER_KEY = 'receive-work:legacy-conversion:v1';

/** The log code of an open that deleted legacy received content. */
export const LEGACY_RECEIVED_CONTENT_DELETED = 'LEGACY_RECEIVED_CONTENT_DELETED';

/** The key prefix of a legacy row that SDK 11 wrote: `received-content:<id>`. */
const LEGACY_RECEIVED_CONTENT_KEY_PREFIX = 'received-content:';

const STAGES = new Set(['decrypted', 'receipt-due', 'awaiting-completion']);
const ORIGINS = new Set(['relay', 'signal-relay', 'caller']);
const MESSAGE_TYPES = new Set(['prekey_bundle', 'ciphertext', 'sender_key']);

/**
 * The two names of the Relay receipt decision of a receive record. This
 * release writes `relayOwnsReceipt`, so that an earlier SDK 14 release reads
 * each record. It reads both names. A record that holds both names with
 * different values is refused.
 */
const RECEIPT_DECISION: RenamedMember = {
  newName: 'signalProtocolRelayOwnsReceipt',
  earlierName: 'relayOwnsReceipt',
  operation: 'receiveWork',
};

/**
 * Tell whether a receive record holds a Relay delivery. This release writes
 * `relay`, and it reads `relay` and `signal-relay`, the value of a later
 * release.
 */
export function isSignalProtocolRelayOrigin(origin: ReceiveWorkRecord['origin']): boolean {
  return origin !== 'caller';
}

/**
 * The origin that this release reports for a receive record: `relay` or
 * `caller`. A stored `signal-relay` is reported as `relay`.
 */
export function reportedReceiveWorkOrigin(
  origin: ReceiveWorkRecord['origin']
): 'relay' | 'caller' {
  return origin === 'caller' ? 'caller' : 'relay';
}

/**
 * The Relay receipt decision of a receive record, from either name. The new
 * name wins. Undefined means that the record holds no decision.
 *
 * @throws SignalProtocolRelayNameConflictError when the two names hold
 *   different values.
 */
export function signalProtocolRelayOwnsReceipt(record: ReceiveWorkRecord): boolean | undefined {
  return readRenamedOption(
    record.signalProtocolRelayOwnsReceipt,
    record.relayOwnsReceipt,
    RECEIPT_DECISION
  );
}

/**
 * The record with the Relay receipt decision `owned`. The record holds the
 * decision under `relayOwnsReceipt`, and also under
 * `signalProtocolRelayOwnsReceipt` when it already holds that name, so the
 * two names agree.
 */
export function withSignalProtocolRelayOwnsReceipt(
  record: ReceiveWorkRecord,
  owned: boolean
): ReceiveWorkRecord {
  return {
    ...record,
    relayOwnsReceipt: owned,
    ...(record.signalProtocolRelayOwnsReceipt !== undefined && {
      signalProtocolRelayOwnsReceipt: owned,
    }),
  };
}

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
 * Tell whether a value is the `received` key of a receive record. Two shapes
 * pass:
 *
 * - The key of this release: `senderUserId` and `timestamp` only.
 * - The SDK 13.x key: `senderUserId`, `senderDeviceId` as a safe integer,
 *   `timestamp` and `contentDigest` as a string. A receive record that SDK
 *   13.x wrote completes through the same reader, and the completion records
 *   the key under its sender user and timestamp only. A receive record lives
 *   at most `MAX_RECEIVE_WORK_AGE_MS` (30 days), which bounds this window.
 *   The next major SDK version after this one removes this shape.
 */
const isReceivedKey = (value: unknown): boolean => {
  const key = value as Record<string, unknown> | null;
  if (
    key === null ||
    typeof key !== 'object' ||
    !isNonEmptyString(key.senderUserId) ||
    typeof key.timestamp !== 'number' ||
    !Number.isFinite(key.timestamp)
  ) {
    return false;
  }
  const fields = Object.keys(key).length;
  if (fields === 2) return true;
  return fields === 4 && isSafeInteger(key.senderDeviceId) && isString(key.contentDigest);
};

/**
 * Check the shape of one receive record. Throws on a record that a store
 * must not accept or return.
 *
 * @throws SignalProtocolRelayNameConflictError when `relayOwnsReceipt` and
 *   `signalProtocolRelayOwnsReceipt` hold different values.
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
    !isOptional(candidate.signalProtocolRelayOwnsReceipt, isBoolean) ||
    !isOptional(
      candidate.hookAttempts,
      (value) => isSafeInteger(value) && (value as number) > 0
    ) ||
    !isOptional(candidate.failedEnvelopeId, isNonEmptyString) ||
    !isOptional(candidate.received, isReceivedKey)
  ) {
    throw new Error('Invalid receive-work record');
  }
  signalProtocolRelayOwnsReceipt(record);
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

/** The legacy rows of one store, as its adapter keeps them. */
interface LegacyReceivedContentRows {
  /** The keys of every legacy row whose key starts with `prefix`. */
  listKeys(prefix: string): Promise<string[]>;
  /** The stored text of one legacy row, after any record cipher. Throws when unreadable. */
  read(key: string): Promise<string | null>;
  /** Delete one legacy row. */
  delete(key: string): Promise<void>;
}

/**
 * Parse one legacy row as the received content that SDK 11 wrote. Throws on
 * a row that does not parse.
 */
function parseLegacyReceivedContent(value: string, id: string): void {
  const record = JSON.parse(value) as {
    id?: unknown;
    plaintext?: unknown;
    receivedAt?: unknown;
    groupId?: unknown;
  };
  if (
    record.id !== id ||
    typeof record.plaintext !== 'string' ||
    !Number.isSafeInteger(record.receivedAt) ||
    (record.receivedAt as number) <= 0 ||
    (record.groupId !== undefined &&
      (typeof record.groupId !== 'string' || record.groupId.length === 0))
  ) {
    throw new Error('Invalid received-content record');
  }
}

/** Tell whether one legacy row parses as the received content of SDK 11. */
async function isReadableLegacyRow(
  rows: LegacyReceivedContentRows,
  key: string
): Promise<boolean | null> {
  let value: string | null;
  try {
    value = await rows.read(key);
  } catch {
    return false;
  }
  if (value === null) return null;
  try {
    parseLegacyReceivedContent(value, key.slice(LEGACY_RECEIVED_CONTENT_KEY_PREFIX.length));
    return true;
  } catch {
    return false;
  }
}

/** Tell whether one stored record is a converted legacy row that waits for its envelope. */
function isAwaitingEnvelope(record: ReceiveWorkRecord): boolean {
  return (record as unknown as { awaitingEnvelope?: unknown }).awaitingEnvelope === true;
}

/**
 * Delete the received content that SDK 11 and the legacy conversion of
 * SDK 13.x left, at each open of a durable store.
 *
 * The sweep deletes each receive record with `awaitingEnvelope: true`, which
 * the conversion wrote, then each legacy row under `received-content:<id>`,
 * and then the marker of the conversion. A record of this release always
 * carries the sender fields of its envelope, so no later read of the open
 * finds a converted record. A converted record waits for an envelope that
 * the Relay keeps for at most its retention period, 30 days in production,
 * and no version gave its content to the application. A device that
 * received the content on SDK 11 inside that period loses the row here,
 * where 13.x would have completed it on redelivery.
 *
 * No marker guards the sweep. Each open lists the records and the legacy
 * rows again, so a sweep that stops deletes the rest at the next open. An
 * open that deleted at least one record or row logs one line with
 * `LEGACY_RECEIVED_CONTENT_DELETED`: `count` is every deleted record and
 * row, and `readable` is the legacy rows that parse as SDK 11 received
 * content. The line holds no key and no value.
 */
export async function sweepLegacyReceivedContent(
  store: Pick<
    SignalProtocolLocalStore,
    'listReceiveWork' | 'completeReceiveWork' | 'getMetadata' | 'deleteMetadata'
  >,
  rows: LegacyReceivedContentRows,
  logger: Pick<Required<Logger>, 'warn'>
): Promise<void> {
  let count = 0;
  let readable = 0;
  let after: ReceiveWorkQuery['after'];
  for (;;) {
    const page = await store.listReceiveWork(after === undefined ? {} : { after });
    for (const record of page) {
      if (!isAwaitingEnvelope(record)) continue;
      if (await store.completeReceiveWork(record.workId, record.revision)) count += 1;
    }
    const last = page.at(-1);
    if (last === undefined) break;
    after = { arrivalSeq: last.arrivalSeq, workId: last.workId };
  }
  for (const key of await rows.listKeys(LEGACY_RECEIVED_CONTENT_KEY_PREFIX)) {
    const parsed = await isReadableLegacyRow(rows, key);
    if (parsed === null) continue;
    await rows.delete(key);
    count += 1;
    if (parsed) readable += 1;
  }
  if ((await store.getMetadata(LEGACY_RECEIVED_CONTENT_MARKER_KEY)) !== null) {
    await store.deleteMetadata(LEGACY_RECEIVED_CONTENT_MARKER_KEY);
  }
  if (count > 0) logger.warn(LEGACY_RECEIVED_CONTENT_DELETED, { count, readable });
}
