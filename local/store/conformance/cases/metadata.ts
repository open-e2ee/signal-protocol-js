/**
 * The metadata cases: compare-and-set on a value, on an absent value, and
 * among concurrent calls, the optional listing of keys by prefix, and the
 * listing of the send intents that the SDK send driver acts on.
 */

import { listOpenOutgoingIntents } from '../../reliability';
import { assertEqual, fail } from '../checks';
import type { LocalStoreConformanceCase } from '../types';

/** The number of concurrent compare-and-set calls on one absent value. */
const CONCURRENT_CALLS = 8;

/** The prefix of the listing case. */
const LIST_PREFIX = 'conformance-list:';

/**
 * The keys of the listing case after the prefix, in ascending UTF-16 code
 * unit order. The surrogate pair of U+1F600 sorts before U+FF21 in UTF-16
 * order, but after it in code point order and in UTF-8 byte order.
 */
const LISTED_SUFFIXES = ['B', 'a', 'a:1', 'b', '\u00e9', '\ud83d\ude00', '\uff21'];

/** Keys next to the prefix that a listing of the prefix must not return. */
const UNLISTED_KEYS = [
  'conformance-lis',
  'conformance-list',
  'conformance-list9',
  'conformance-list;a',
  'conformance-lisa',
];

/** The prefix of the default page size check. */
const PAGE_PREFIX = 'conformance-page:';

/** The keys that the listing returns when the query sets no limit. */
const DEFAULT_LIMIT = 100;

/** The outbox keys of the SDK send intents. */
const OUTBOX_PREFIX = 'reliability:exact-ciphertext-outbox:v2';
const OUTBOX_RECORD_PREFIX = OUTBOX_PREFIX + ':record:';

interface CompareAndSetStep {
  expected: string | null;
  value: string | null;
  result: boolean;
  stored: string | null;
  label: string;
}

function step(
  expected: string | null,
  value: string | null,
  result: boolean,
  stored: string | null,
  label: string
): CompareAndSetStep {
  return { expected: expected, value: value, result: result, stored: stored, label: label };
}

/**
 * A send intent that ended at its deadline and has its report, with the
 * manual resends `resends`. The record holds the fields that the listing
 * reads.
 */
function endedIntent(clientMessageId: string, now: number, resends: unknown[]): string {
  return JSON.stringify({
    kind: 'direct',
    clientMessageId: clientMessageId,
    recipientId: 'conformance-recipient',
    plaintextDigest: 'conformance-digest',
    clientTimestamp: now,
    createdAt: now,
    deadlineAt: now,
    deviceMessages: [],
    syncMessages: [],
    outcome: 'acceptance-unknown',
    outcomeReportedAt: now,
    manualResends: resends,
  });
}

/**
 * Manual resend number `n` of `clientMessageId`: open, ended with the end
 * `outcome`, or, for `completed`, ended with a result and no outcome.
 */
function manualResend(clientMessageId: string, n: number, now: number, outcome?: string) {
  const manualMessageId = clientMessageId + ':manual:' + n;
  let end = {};
  if (outcome === 'completed') {
    end = {
      result: {
        clientMessageId: clientMessageId,
        messageId: manualMessageId,
        timestamp: now,
        recipientDeviceCount: 1,
      },
    };
  } else if (outcome !== undefined) {
    end = { outcome: outcome, outcomeReportedAt: now };
  }
  return Object.assign(
    {
      manualMessageId: manualMessageId,
      createdAt: now,
      operationEpochMilliseconds: now,
      deadlineAt: now + 1,
      messages: [],
    },
    end
  );
}

function threeDigits(index: number): string {
  return ('00' + index).slice(-3);
}

export const metadataCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'metadata compare-and-set',
    run: async function metadataCompareAndSet(context) {
      const store = context.store;
      const key = 'conformance-compare-and-set';
      const steps: CompareAndSetStep[] = [
        step(null, 'a', true, 'a', 'a write that expects an absent value'),
        step(null, 'b', false, 'a', 'a write that expects an absent value over a value'),
        step('a', 'b', true, 'b', 'a write that expects the stored value'),
        step('x', 'c', false, 'b', 'a write that expects a different value'),
        step('b', null, true, null, 'a delete that expects the stored value'),
        step('b', 'd', false, null, 'a write that expects a value over an absent value'),
      ];
      for (const next of steps) {
        assertEqual(
          await store.compareAndSetMetadata(key, next.expected, next.value),
          next.result,
          'the result of ' + next.label
        );
        assertEqual(await store.getMetadata(key), next.stored, 'the value after ' + next.label);
      }

      const raced = 'conformance-compare-and-set-race';
      const calls: Array<Promise<boolean>> = [];
      for (let index = 0; index < CONCURRENT_CALLS; index += 1) {
        calls.push(store.compareAndSetMetadata(raced, null, 'writer-' + index));
      }
      const results = await Promise.all(calls);
      const winners: number[] = [];
      results.forEach(function collect(won, index) {
        if (won) winners.push(index);
      });
      if (winners.length !== 1) {
        fail(
          'concurrent writes that expect an absent value: expected one winner, got ' +
            JSON.stringify(winners)
        );
      }
      assertEqual(
        await store.getMetadata(raced),
        'writer-' + winners[0],
        'the value after concurrent writes'
      );
    },
  },
  {
    name: 'lists metadata keys by prefix in order, with after and limit',
    applies: function declaresMetadataKeyListing(store) {
      return typeof store.listMetadataKeys === 'function';
    },
    run: async function metadataKeyListing(context) {
      const store = context.store;
      const listed = LISTED_SUFFIXES.map(function prefixed(suffix) {
        return LIST_PREFIX + suffix;
      });
      const written = UNLISTED_KEYS.concat(listed.slice().reverse());
      for (const key of written) await store.setMetadata(key, 'listed');

      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX }),
        listed,
        'the keys of the prefix'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, limit: 3 }),
        listed.slice(0, 3),
        'the first page of three keys'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, after: listed[2], limit: 3 }),
        listed.slice(3, 6),
        'the page of three keys after the third key'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, after: listed[5] }),
        listed.slice(6),
        'the keys after the sixth key'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, after: listed[6] }),
        [],
        'the keys after the last key'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, after: LIST_PREFIX + 'a' }),
        listed.slice(2),
        'the keys after a key that the store holds'
      );
      assertEqual(
        await store.listMetadataKeys!({ prefix: LIST_PREFIX, after: 'conformance-lis' }),
        listed,
        'the keys after a key below the prefix'
      );

      const page: string[] = [];
      for (let index = 0; index <= DEFAULT_LIMIT; index += 1) {
        page.push(PAGE_PREFIX + threeDigits(index));
      }
      for (const key of page) await store.setMetadata(key, 'paged');
      assertEqual(
        await store.listMetadataKeys!({ prefix: PAGE_PREFIX }),
        page.slice(0, DEFAULT_LIMIT),
        'the keys of a query with no limit'
      );
    },
  },
  {
    name:
      'a store that holds an outbox record, an outbox bucket row and the outbox manifest row ' +
      'returns only the record key for the record prefix',
    applies: function declaresMetadataKeyListing(store) {
      return typeof store.listMetadataKeys === 'function';
    },
    run: async function metadataRecordPrefix(context) {
      const store = context.store;
      const record = OUTBOX_RECORD_PREFIX + 'conformance-intent';
      await store.setMetadata(record, '{}');
      await store.setMetadata(OUTBOX_PREFIX + ':bucket:20000', '[]');
      await store.setMetadata(OUTBOX_PREFIX + ':manifest', '[]');
      assertEqual(
        await store.listMetadataKeys!({ prefix: OUTBOX_RECORD_PREFIX }),
        [record],
        'the keys of the outbox record prefix'
      );
    },
  },
  {
    name:
      'lists an intent that has an outcome, no pending report and an open manual entry, ' +
      'and leaves out one whose manual entries all have an outcome or a result',
    applies: function declaresMetadataKeyListing(store) {
      return typeof store.listMetadataKeys === 'function';
    },
    run: async function openManualResendListing(context) {
      const store = context.store;
      const now = Date.now();
      const open = 'conformance-open-resend';
      const closed = 'conformance-closed-resend';
      // A resend writes its entry over the ended record of the intent.
      await store.setMetadata(OUTBOX_RECORD_PREFIX + open, endedIntent(open, now, []));
      await store.setMetadata(
        OUTBOX_RECORD_PREFIX + open,
        endedIntent(open, now, [
          manualResend(open, 1, now, 'acceptance-unknown'),
          manualResend(open, 2, now),
        ])
      );
      await store.setMetadata(
        OUTBOX_RECORD_PREFIX + closed,
        endedIntent(closed, now, [
          manualResend(closed, 1, now, 'acceptance-unknown'),
          manualResend(closed, 2, now, 'failed'),
          manualResend(closed, 3, now, 'completed'),
        ])
      );
      const listed = await listOpenOutgoingIntents(store, now);
      assertEqual(
        listed === undefined
          ? undefined
          : listed.map(function clientMessageIdOf(intent) {
              return intent.clientMessageId;
            }),
        [open],
        'the send intents that the send driver acts on'
      );
    },
  },
];
