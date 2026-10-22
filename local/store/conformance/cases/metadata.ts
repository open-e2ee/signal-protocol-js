/**
 * The metadata case: compare-and-set on a value, on an absent value, and
 * among concurrent calls.
 */

import { assertEqual, fail } from '../checks';
import type { LocalStoreConformanceCase } from '../types';

/** The number of concurrent compare-and-set calls on one absent value. */
const CONCURRENT_CALLS = 8;

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
];
