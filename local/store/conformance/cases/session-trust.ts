/**
 * The session trust cases: the atomic commit of a session, its contact
 * identity, and its receive record, and the rollback of that commit.
 */

import { ProtocolAddress } from '../../../../types/address';
import type { SessionTrustCommit, SignalProtocolLocalStore } from '../../../../types/api';
import { assertAbsent, assertEqual, expectRejection } from '../checks';
import { contactIdentity, receiveWork, sessionRecord } from '../records';
import type { LocalStoreConformanceCase } from '../types';

/** A one-time prekey ID that no case stores. */
const MISSING_ONE_TIME_PREKEY_ID = 4242;

function trustCommit(
  address: ProtocolAddress,
  receivedMessages: number,
  contactSeed: number,
  extra: Partial<SessionTrustCommit> = {}
): SessionTrustCommit {
  return {
    address: address,
    record: sessionRecord(address, receivedMessages),
    contactIdentity: contactIdentity(contactSeed),
    contactIdentityType: 'aci',
    localIdentityType: 'aci',
    ...extra,
  };
}

async function pinnedContact(
  store: SignalProtocolLocalStore,
  address: ProtocolAddress
): Promise<unknown> {
  const record = await store.getContactIdentity(address, 'aci');
  return record === null || record === undefined ? null : record.identity;
}

export const sessionTrustCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'session trust commit',
    run: async function sessionTrustCommit(context) {
      const store = context.store;
      const address = ProtocolAddress.create('conformance-trust-user', 1);
      await store.commitSessionTrust(trustCommit(address, 1, 1));
      assertEqual(
        await store.getSessionRecord(address),
        sessionRecord(address, 1),
        'the session of a commit'
      );
      assertEqual(await pinnedContact(store, address), contactIdentity(1), 'the pinned contact identity');

      await expectRejection(
        store.commitSessionTrust(trustCommit(address, 2, 11)),
        'a commit with a changed contact identity'
      );
      assertEqual(
        await store.getSessionRecord(address),
        sessionRecord(address, 1),
        'the session after a commit with a changed contact identity'
      );
      assertEqual(
        await pinnedContact(store, address),
        contactIdentity(1),
        'the contact identity after a commit with a changed contact identity'
      );

      const refused = ProtocolAddress.create('conformance-refused-user', 1);
      await expectRejection(
        store.commitSessionTrust(
          trustCommit(refused, 1, 1, { oneTimePreKeyId: MISSING_ONE_TIME_PREKEY_ID })
        ),
        'a commit that consumes a missing one-time prekey'
      );
      assertAbsent(
        await store.getSessionRecord(refused),
        'the session of a commit that consumes a missing one-time prekey'
      );
      assertAbsent(
        await pinnedContact(store, refused),
        'the contact identity of a commit that consumes a missing one-time prekey'
      );
    },
  },
  {
    name: 'session trust commit rollback',
    needs: 'armWriteFailure',
    run: async function sessionTrustCommitRollback(context) {
      const store = context.store;
      const known = ProtocolAddress.create('conformance-rollback-known-user', 1);
      await store.commitSessionTrust(trustCommit(known, 1, 1));
      const knownWork = receiveWork('conformance-rollback-known-work');
      context.armWriteFailure();
      await expectRejection(
        store.commitSessionTrust(trustCommit(known, 2, 1, { receiveWork: knownWork })),
        'a commit of a known session with an armed write failure'
      );
      assertEqual(
        await store.getSessionRecord(known),
        sessionRecord(known, 1),
        'the session after a failed commit'
      );
      assertAbsent(
        await store.getReceiveWork(knownWork.workId),
        'the receive record of a failed commit'
      );

      const fresh = ProtocolAddress.create('conformance-rollback-new-user', 1);
      const freshWork = receiveWork('conformance-rollback-new-work');
      context.armWriteFailure();
      await expectRejection(
        store.commitSessionTrust(trustCommit(fresh, 1, 21, { receiveWork: freshWork })),
        'a first commit with an armed write failure'
      );
      assertAbsent(await store.getSessionRecord(fresh), 'the session of a failed first commit');
      assertAbsent(
        await pinnedContact(store, fresh),
        'the contact identity of a failed first commit'
      );
      assertAbsent(
        await store.getReceiveWork(freshWork.workId),
        'the receive record of a failed first commit'
      );
    },
  },
];
