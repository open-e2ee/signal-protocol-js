/**
 * The durability case: each kind of write survives a reopen of the store.
 */

import { ProtocolAddress } from '../../../../types/address';
import { assertEqual } from '../checks';
import {
  contactIdentity,
  receiveWork,
  SENDER_KEY_ID,
  senderKeyState,
  sessionRecord,
  skippedMessageKey,
} from '../records';
import type { LocalStoreConformanceCase } from '../types';

export const durabilityCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'durability after reopen',
    needs: 'reopen',
    run: async function durabilityAfterReopen(context) {
      const store = context.store;
      const address = ProtocolAddress.create('conformance-durable-user', 1);
      const groupId = 'conformance-durable-group';
      const memberId = 'conformance-durable-member';
      const work = receiveWork('conformance-durable-work', { groupId: groupId });

      await store.storeSessionRecord(address, sessionRecord(address, 1));
      await store.saveContactIdentity(address, contactIdentity(1), 'aci');
      await store.storeSenderKeyRecord(groupId, memberId, 1, [senderKeyState(1)]);
      await store.storeSkippedSenderKey(groupId, memberId, 1, SENDER_KEY_ID, 2, skippedMessageKey(2));
      await store.setMetadata('conformance-durable-metadata', 'durable value');
      await store.putReceiveWork(work, null);

      const reopened = await context.reopen();
      assertEqual(
        await reopened.getSessionRecord(address),
        sessionRecord(address, 1),
        'the session after a reopen'
      );
      const contact = await reopened.getContactIdentity(address, 'aci');
      assertEqual(
        contact === null || contact === undefined ? null : contact.identity,
        contactIdentity(1),
        'the contact identity after a reopen'
      );
      assertEqual(
        await reopened.getSenderKeyRecord(groupId, memberId, 1),
        [senderKeyState(1)],
        'the sender key record after a reopen'
      );
      assertEqual(
        await reopened.getSkippedSenderKey(groupId, memberId, 1, SENDER_KEY_ID, 2),
        skippedMessageKey(2),
        'the skipped key after a reopen'
      );
      assertEqual(
        await reopened.getMetadata('conformance-durable-metadata'),
        'durable value',
        'the metadata after a reopen'
      );
      assertEqual(
        await reopened.getReceiveWork(work.workId),
        work,
        'the receive record after a reopen'
      );
    },
  },
];
