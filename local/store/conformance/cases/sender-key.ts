/**
 * The sender key cases: the atomic commit of a sender key record with its
 * receive effects, and the rollback of that commit.
 */

import { assertAbsent, assertEqual, expectRejection } from '../checks';
import {
  receiveWork,
  SENDER_KEY_ID,
  senderKeyState,
  skippedMessageKey,
} from '../records';
import type { LocalStoreConformanceCase } from '../types';

const GROUP_ID = 'conformance-group';
const MEMBER_ID = 'conformance-member';
const DEVICE_ID = 1;

function skippedKey(chainIndex: number): {
  senderKeyId: string;
  chainIndex: number;
  messageKey: { cipherKey: string; iv: string };
} {
  return { senderKeyId: SENDER_KEY_ID, chainIndex: chainIndex, messageKey: skippedMessageKey(chainIndex) };
}

export const senderKeyCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'sender key receive commit',
    run: async function senderKeyReceiveCommit(context) {
      const store = context.store;
      await store.storeSkippedSenderKey(
        GROUP_ID,
        MEMBER_ID,
        DEVICE_ID,
        SENDER_KEY_ID,
        1,
        skippedMessageKey(1)
      );
      const work = receiveWork('conformance-sender-key-work', { groupId: GROUP_ID });
      await store.storeSenderKeyRecord(GROUP_ID, MEMBER_ID, DEVICE_ID, [senderKeyState(2)], {
        work: work,
        consumedSkippedKey: { senderKeyId: SENDER_KEY_ID, chainIndex: 1 },
      });
      assertEqual(
        await store.getSenderKeyRecord(GROUP_ID, MEMBER_ID, DEVICE_ID),
        [senderKeyState(2)],
        'the sender key record of a receive commit'
      );
      assertEqual(
        await store.getReceiveWork(work.workId),
        work,
        'the receive record of a sender key commit'
      );
      assertAbsent(
        await store.getSkippedSenderKey(GROUP_ID, MEMBER_ID, DEVICE_ID, SENDER_KEY_ID, 1),
        'the consumed skipped key'
      );

      const evictingMember = 'conformance-evicting-member';
      await store.storeSenderKeyRecord(GROUP_ID, evictingMember, DEVICE_ID, [senderKeyState(4)], {
        skippedKeys: { maxSkippedKeys: 2, keys: [skippedKey(1), skippedKey(2), skippedKey(3)] },
      });
      assertEqual(
        await store.countSkippedSenderKeys(GROUP_ID, evictingMember, DEVICE_ID),
        2,
        'the skipped key count after an eviction'
      );
      assertAbsent(
        await store.getSkippedSenderKey(GROUP_ID, evictingMember, DEVICE_ID, SENDER_KEY_ID, 1),
        'the skipped key with the lowest chain index after an eviction'
      );
      for (const chainIndex of [2, 3]) {
        assertEqual(
          await store.getSkippedSenderKey(
            GROUP_ID,
            evictingMember,
            DEVICE_ID,
            SENDER_KEY_ID,
            chainIndex
          ),
          skippedMessageKey(chainIndex),
          'the kept skipped key at chain index ' + chainIndex + ' after an eviction'
        );
      }
    },
  },
  {
    name: 'sender key receive commit rollback',
    needs: 'armWriteFailure',
    run: async function senderKeyReceiveCommitRollback(context) {
      const store = context.store;
      await store.storeSenderKeyRecord(GROUP_ID, MEMBER_ID, DEVICE_ID, [senderKeyState(1)]);
      await store.storeSkippedSenderKey(
        GROUP_ID,
        MEMBER_ID,
        DEVICE_ID,
        SENDER_KEY_ID,
        3,
        skippedMessageKey(3)
      );
      const work = receiveWork('conformance-lost-sender-key-work', { groupId: GROUP_ID });
      context.armWriteFailure();
      await expectRejection(
        store.storeSenderKeyRecord(GROUP_ID, MEMBER_ID, DEVICE_ID, [senderKeyState(5)], {
          work: work,
          consumedSkippedKey: { senderKeyId: SENDER_KEY_ID, chainIndex: 3 },
          skippedKeys: { maxSkippedKeys: 10, keys: [skippedKey(4)] },
        }),
        'a sender key commit with an armed write failure'
      );
      assertEqual(
        await store.getSenderKeyRecord(GROUP_ID, MEMBER_ID, DEVICE_ID),
        [senderKeyState(1)],
        'the sender key record after a failed commit'
      );
      assertEqual(
        await store.getSkippedSenderKey(GROUP_ID, MEMBER_ID, DEVICE_ID, SENDER_KEY_ID, 3),
        skippedMessageKey(3),
        'the skipped key that a failed commit consumed'
      );
      assertAbsent(
        await store.getSkippedSenderKey(GROUP_ID, MEMBER_ID, DEVICE_ID, SENDER_KEY_ID, 4),
        'the skipped key that a failed commit added'
      );
      assertAbsent(
        await store.getReceiveWork(work.workId),
        'the receive record of a failed sender key commit'
      );
    },
  },
];
