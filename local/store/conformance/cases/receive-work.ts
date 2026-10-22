/**
 * The receive record cases: the insert and the compare-and-set of one
 * record, the listing in arrival order, and the atomic completion with its
 * usage counts.
 */

import type {
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  ReceiveWorkStage,
  ReceiveWorkUsage,
} from '../../../../types/api';
import { assertAbsent, assertEqual, expectRejection } from '../checks';
import { receiveWork } from '../records';
import type { LocalStoreConformanceCase } from '../types';

/** The number of records of the listing case. It is one above the default page size. */
const LISTED_RECORDS = 101;

function compareWorkIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function inArrivalOrder(a: ReceiveWorkRecord, b: ReceiveWorkRecord): number {
  return a.arrivalSeq - b.arrivalSeq || compareWorkIds(a.workId, b.workId);
}

function isAfter(record: ReceiveWorkRecord, cursor: ReceiveWorkRecord): boolean {
  return inArrivalOrder(record, cursor) > 0;
}

function workIds(records: readonly ReceiveWorkRecord[]): string[] {
  return records.map(function workIdOf(record) {
    return record.workId;
  });
}

function usageOf(records: readonly ReceiveWorkRecord[]): ReceiveWorkUsage {
  let bytes = 0;
  for (const record of records) bytes += record.sizeBytes;
  return { items: records.length, bytes: bytes };
}

/**
 * The records of the listing case. The work IDs have no zero padding, so
 * their text order is not their number order. Groups of three records share
 * one arrival sequence, and the insert order is not the arrival order.
 */
function listedRecords(): ReceiveWorkRecord[] {
  const stages: readonly ReceiveWorkStage[] = ['decrypted', 'receipt-due', 'awaiting-completion'];
  const records: ReceiveWorkRecord[] = [];
  for (let index = 0; index < LISTED_RECORDS; index += 1) {
    const stage = stages[index % stages.length];
    records.push(
      receiveWork('conformance-list-' + ((index * 37) % LISTED_RECORDS), {
        arrivalSeq: Math.floor(((index * 53) % LISTED_RECORDS) / 3) + 1,
        stage: stage,
        dueAt: 1_000 + (index % 5) * 100,
        plaintext: stage === 'receipt-due' ? undefined : 'listed content ' + index,
      })
    );
  }
  return records;
}

async function expectListing(
  list: (query?: ReceiveWorkQuery) => Promise<ReceiveWorkRecord[]>,
  query: ReceiveWorkQuery | undefined,
  expected: readonly ReceiveWorkRecord[],
  label: string
): Promise<void> {
  assertEqual(workIds(await list(query)), workIds(expected), label);
}

export const receiveWorkCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'receive record insert and compare-and-set',
    run: async function receiveRecordInsert(context) {
      const store = context.store;
      const first = receiveWork('conformance-put');
      assertEqual(await store.putReceiveWork(first, null), true, 'an insert of a new record');
      assertEqual(await store.getReceiveWork(first.workId), first, 'the inserted record');

      const clash = receiveWork('conformance-put', { arrivalSeq: 2, plaintext: 'other content' });
      assertEqual(
        await store.putReceiveWork(clash, null),
        false,
        'an insert over an existing record'
      );
      assertEqual(
        await store.getReceiveWork(first.workId),
        first,
        'the record after an insert over it'
      );

      const second = receiveWork('conformance-put', { revision: 1, stage: 'awaiting-completion' });
      assertEqual(
        await store.putReceiveWork(second, 0),
        true,
        'a replace that names the stored revision'
      );
      assertEqual(await store.getReceiveWork(first.workId), second, 'the replaced record');

      const stale = receiveWork('conformance-put', { revision: 2, stage: 'receipt-due', plaintext: undefined });
      assertEqual(
        await store.putReceiveWork(stale, 0),
        false,
        'a replace that names a stale revision'
      );
      assertEqual(
        await store.getReceiveWork(first.workId),
        second,
        'the record after a replace that names a stale revision'
      );

      const missing = receiveWork('conformance-put-missing', { revision: 1 });
      assertEqual(
        await store.putReceiveWork(missing, 0),
        false,
        'a replace of an absent record'
      );
      assertAbsent(
        await store.getReceiveWork(missing.workId),
        'the record of a replace of an absent record'
      );
    },
  },
  {
    name: 'receive record listing',
    run: async function receiveRecordListing(context) {
      const store = context.store;
      const list = function list(query?: ReceiveWorkQuery): Promise<ReceiveWorkRecord[]> {
        return store.listReceiveWork(query);
      };
      const records = listedRecords();
      for (const record of records) await store.putReceiveWork(record, null);
      const ordered = records.slice().sort(inArrivalOrder);

      assertEqual(await list(), ordered.slice(0, 100), 'the first page of records');
      await expectListing(list, { limit: 200 }, ordered, 'every record in arrival order');
      await expectListing(list, { limit: 7 }, ordered.slice(0, 7), 'a page with a limit');

      for (const position of [0, 49, 50, LISTED_RECORDS - 2]) {
        const cursor = ordered[position];
        await expectListing(
          list,
          { after: { arrivalSeq: cursor.arrivalSeq, workId: cursor.workId }, limit: 200 },
          ordered.slice(position + 1),
          'the records after the record at position ' + position
        );
      }
      const last = ordered[LISTED_RECORDS - 1];
      await expectListing(
        list,
        { after: { arrivalSeq: last.arrivalSeq, workId: last.workId } },
        [],
        'the records after the last record'
      );

      for (const stage of ['decrypted', 'receipt-due', 'awaiting-completion'] as const) {
        await expectListing(
          list,
          { stage: stage, limit: 200 },
          ordered.filter(function inStage(record) {
            return record.stage === stage;
          }),
          'the records in stage ' + stage
        );
      }
      await expectListing(
        list,
        { dueBy: 1_200, limit: 200 },
        ordered.filter(function due(record) {
          return record.dueAt <= 1_200;
        }),
        'the records due at a time'
      );
      const cursor = ordered[10];
      await expectListing(
        list,
        {
          stage: 'decrypted',
          dueBy: 1_300,
          after: { arrivalSeq: cursor.arrivalSeq, workId: cursor.workId },
          limit: 5,
        },
        ordered
          .filter(function matches(record) {
            return record.stage === 'decrypted' && record.dueAt <= 1_300 && isAfter(record, cursor);
          })
          .slice(0, 5),
        'a page of the filtered records after a cursor'
      );
      await expectRejection(list({ limit: 0 }), 'a listing with a limit of zero');
    },
  },
  {
    name: 'receive record completion and usage',
    run: async function receiveRecordCompletion(context) {
      const store = context.store;
      const groupId = 'conformance-completion-group';
      const plain = receiveWork('conformance-complete-plain', { arrivalSeq: 1 });
      const blocked = receiveWork('conformance-complete-blocked', {
        arrivalSeq: 2,
        groupId: groupId,
        blockedOn: 'group-update',
      });
      const waiting = receiveWork('conformance-complete-waiting', { arrivalSeq: 3, groupId: groupId });
      for (const record of [plain, blocked, waiting]) await store.putReceiveWork(record, null);
      await store.setMetadata('conformance-complete-deleted', 'old');

      assertEqual(
        await store.receiveWorkUsage(),
        usageOf([plain, blocked, waiting]),
        'the usage of every record'
      );
      assertEqual(
        await store.receiveWorkUsage({ groupId: groupId }),
        usageOf([blocked]),
        'the usage of the records that wait for a group update'
      );

      assertEqual(
        await store.completeReceiveWork(plain.workId, 1, [
          { key: 'conformance-complete-set', value: 'done' },
        ]),
        false,
        'a completion that names a stale revision'
      );
      assertEqual(
        await store.getReceiveWork(plain.workId),
        plain,
        'the record after a completion that names a stale revision'
      );
      assertAbsent(
        await store.getMetadata('conformance-complete-set'),
        'the metadata of a completion that names a stale revision'
      );

      assertEqual(
        await store.completeReceiveWork(plain.workId, 0, [
          { key: 'conformance-complete-set', value: 'done' },
          { key: 'conformance-complete-deleted', value: null },
        ]),
        true,
        'a completion that names the stored revision'
      );
      assertAbsent(await store.getReceiveWork(plain.workId), 'a completed record');
      assertEqual(
        await store.getMetadata('conformance-complete-set'),
        'done',
        'the metadata that a completion sets'
      );
      assertAbsent(
        await store.getMetadata('conformance-complete-deleted'),
        'the metadata that a completion deletes'
      );
      assertEqual(
        await store.receiveWorkUsage(),
        usageOf([blocked, waiting]),
        'the usage after a completion'
      );

      assertEqual(
        await store.completeReceiveWork(blocked.workId, 0),
        true,
        'a completion of a record that waits for a group update'
      );
      assertEqual(
        await store.receiveWorkUsage({ groupId: groupId }),
        usageOf([]),
        'the group usage after a completion'
      );
      assertEqual(
        await store.completeReceiveWork(plain.workId, 0),
        false,
        'a completion of an absent record'
      );
    },
  },
];
