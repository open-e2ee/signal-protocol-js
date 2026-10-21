/**
 * The admission of the receive queue: the bounds check that runs before a
 * decrypt.
 *
 * Only records that wait accumulate, so the bounds count every stored
 * receive record. A decrypt runs only when the queue has room:
 *
 * - The global bound: fewer than `maxItems` records and fewer than
 *   `maxBytes` bytes.
 * - The group bound, for a sender-key message: the records of its group
 *   that wait for a group update hold fewer than `blockedGroupShare` of
 *   each global bound. The group resolves from the distribution identifier
 *   in the frame before the decrypt.
 *
 * A pairwise message decrypts whenever the global bound has room. After its
 * decrypt, a pairwise record that waits for its group counts toward that
 * group, so pairwise content can fill a group past its share up to the
 * global bound.
 *
 * One in-process lock per store covers the check, the decrypt, and the
 * commit of the record, so two receives in one process never pass the
 * check for the same last slot. Two processes that share one store, such
 * as two browser tabs, can each pass the check and overshoot a bound by
 * their own receives in flight. Each process also keeps its own arrival
 * counter, so a record of one process can sort before a record that another
 * process admitted earlier (see `receive-work-seed.ts`).
 */

import type { Logger } from '../logger';
import type { SignalProtocolLocalStore } from '../types/api';
import { createKeyedLocks, withKeyedLock } from '../utils/keyed-lock';
import type { ResolvedReceiveQueuePolicy } from './storage-protection';

const admissionLocks = createKeyedLocks();

/** The store reads of the admission. */
export type ReceiveAdmissionStore = Pick<SignalProtocolLocalStore, 'receiveWorkUsage'>;

/**
 * The bounds of the waiting records of one group.
 *
 * @returns At least one item, so a small `maxItems` still lets one record
 *   of each group wait.
 */
export function blockedGroupBounds(policy: ResolvedReceiveQueuePolicy): {
  readonly items: number;
  readonly bytes: number;
} {
  return {
    items: Math.max(1, Math.floor(policy.maxItems * policy.blockedGroupShare)),
    bytes: Math.max(1, Math.floor(policy.maxBytes * policy.blockedGroupShare)),
  };
}

/**
 * Run one decrypt under the receive admission.
 *
 * @param store - The local store that keeps the receive records.
 * @param policy - The resolved receive queue policy.
 * @param logger - The client logger.
 * @param groupId - The raw group of a sender-key message, or null for a
 *   pairwise message.
 * @param decrypt - The decrypt and the commit of its record.
 * @returns The decrypt result, or null when the queue has no room. Then
 *   nothing is decrypted.
 */
export async function admitReceive<T>(
  store: ReceiveAdmissionStore,
  policy: ResolvedReceiveQueuePolicy,
  logger: Required<Logger>,
  groupId: string | null,
  decrypt: () => Promise<T>
): Promise<{ value: T } | null> {
  return withKeyedLock(admissionLocks, store, 'admission', async () => {
    const usage = await store.receiveWorkUsage();
    if (usage.items >= policy.maxItems || usage.bytes >= policy.maxBytes) {
      logger.warn('The receive queue is full. The message waits at the Relay', {
        category: 'E2EE',
        data: { behavior: 'RECEIVE_QUEUE_FULL', items: usage.items, bytes: usage.bytes },
      });
      return null;
    }
    if (groupId !== null) {
      const group = await store.receiveWorkUsage({ groupId });
      const bounds = blockedGroupBounds(policy);
      if (group.items >= bounds.items || group.bytes >= bounds.bytes) {
        logger.warn('The waiting content of one group fills its share of the receive queue', {
          category: 'E2EE',
          data: { behavior: 'RECEIVE_QUEUE_GROUP_FULL', items: group.items, bytes: group.bytes },
        });
        return null;
      }
    }
    return { value: await decrypt() };
  });
}
