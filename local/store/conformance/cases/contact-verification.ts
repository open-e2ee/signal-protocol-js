/**
 * The contact verification case: a store clears the verification of the
 * pinned identity only, and keeps the pin. The case applies to a store that
 * has the optional `unverifyContactIdentity`.
 */

import { ProtocolAddress } from '../../../../types/address';
import type { SignalProtocolLocalStore } from '../../../../types/api';
import { assertEqual, expectRejection, fail } from '../checks';
import { contactIdentity } from '../records';
import type { LocalStoreConformanceCase } from '../types';

async function trustOf(
  store: SignalProtocolLocalStore,
  address: ProtocolAddress
): Promise<{ identity: unknown; trustState: string; verified: boolean; revision: number }> {
  const record = await store.getContactIdentity(address, 'aci');
  if (!record) fail('the pinned contact identity is missing');
  return {
    identity: record.identity,
    trustState: record.trustState,
    verified: record.verifiedAt !== undefined,
    revision: record.revision,
  };
}

export const contactVerificationCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'contact verification clearing',
    applies: function declaresUnverify(store) {
      return typeof store.unverifyContactIdentity === 'function';
    },
    run: async function contactVerificationClearing(context) {
      const store = context.store;
      const unverify = store.unverifyContactIdentity!.bind(store);
      const address = ProtocolAddress.create('conformance-verification-user', 1);
      await store.saveContactIdentity(address, contactIdentity(41), 'aci');
      await store.verifyContactIdentity(address, contactIdentity(41), 'aci');
      const verified = await trustOf(store, address);
      assertEqual(verified.trustState, 'VERIFIED', 'the trust state after a verification');

      await expectRejection(
        unverify(address, contactIdentity(51), 'aci'),
        'a clearing for an identity that is not pinned'
      );
      assertEqual(
        await trustOf(store, address),
        verified,
        'the contact identity after a clearing for an identity that is not pinned'
      );

      const cleared = {
        identity: contactIdentity(41),
        trustState: 'UNVERIFIED_TOFU',
        verified: false,
        revision: verified.revision,
      };
      await unverify(address, contactIdentity(41), 'aci');
      assertEqual(await trustOf(store, address), cleared, 'the contact identity after a clearing');
      await unverify(address, contactIdentity(41), 'aci');
      assertEqual(
        await trustOf(store, address),
        cleared,
        'the contact identity after a second clearing'
      );

      await expectRejection(
        unverify(ProtocolAddress.create('conformance-unseen-user', 1), contactIdentity(41), 'aci'),
        'a clearing for a contact without a pinned identity'
      );
    },
  },
];
