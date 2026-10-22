/**
 * The identity cases: the overwrite of the local identity key pair and the
 * registration ID of one identity type, and the same writes after a reopen.
 */

import type { IdentityKeyPair } from '../../../../keys';
import { generateIdentityKeyPair } from '../../../../keys/generation';
import type { IdentityType, SignalProtocolLocalStore } from '../../../../types/api';
import { assertEqual, fail } from '../checks';
import type { LocalStoreConformanceCase } from '../types';

const IDENTITY_TYPES: readonly IdentityType[] = ['aci', 'pni'];

/** The first registration ID of each identity type. Each write adds one. */
const FIRST_REGISTRATION_ID: Record<IdentityType, number> = { aci: 1001, pni: 2001 };

interface IdentityRead {
  keyPair: IdentityKeyPair | null;
  registrationId: number;
}

async function readIdentity(
  store: SignalProtocolLocalStore,
  type: IdentityType
): Promise<IdentityRead> {
  return {
    keyPair: await store.getIdentityKey(type),
    registrationId: await store.getLocalRegistrationId(type),
  };
}

/** Write the key pair and its registration ID of one identity type. */
async function writeIdentity(
  store: SignalProtocolLocalStore,
  keyPair: IdentityKeyPair,
  type: IdentityType
): Promise<void> {
  await store.storeIdentityKey(keyPair, type);
  await store.setLocalRegistrationId(keyPair.registrationId, type);
}

/** Assert both reads of each identity type. */
async function assertIdentities(
  store: SignalProtocolLocalStore,
  expected: Record<IdentityType, IdentityKeyPair>,
  label: string
): Promise<void> {
  for (const type of IDENTITY_TYPES) {
    assertEqual(
      await readIdentity(store, type),
      { keyPair: expected[type], registrationId: expected[type].registrationId },
      'the ' + type + ' identity ' + label
    );
  }
}

/**
 * Write a key pair and a registration ID for each identity type, as a new
 * store does. Then, for each type, overwrite the record with the same keys
 * and a new registration ID, as a managed device link does. With `check`,
 * assert both reads of both types after each write.
 */
async function overwriteIdentities(store: SignalProtocolLocalStore, check: boolean): Promise<void> {
  let current: Record<IdentityType, IdentityKeyPair> = {
    aci: { ...(await generateIdentityKeyPair()), registrationId: FIRST_REGISTRATION_ID.aci },
    pni: { ...(await generateIdentityKeyPair()), registrationId: FIRST_REGISTRATION_ID.pni },
  };
  for (const type of IDENTITY_TYPES) await writeIdentity(store, current[type], type);
  if (check) await assertIdentities(store, current, 'after the first write');

  for (const type of IDENTITY_TYPES) {
    const replacement: IdentityKeyPair = {
      ...current[type],
      registrationId: current[type].registrationId + 1,
    };
    await writeIdentity(store, replacement, type);
    current = { ...current, [type]: replacement };
    if (check) {
      await assertIdentities(store, current, 'after the overwrite of the ' + type + ' identity');
    }
  }
}

export const identityCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'identity overwrite',
    run: async function identityOverwrite(context) {
      await overwriteIdentities(context.store, true);
    },
  },
  {
    name: 'identity overwrite after reopen',
    needs: 'reopen',
    run: async function identityOverwriteAfterReopen(context) {
      // The identity overwrite case checks the values. This case checks only
      // that a reopen keeps the values that the store gave before it.
      await overwriteIdentities(context.store, false);
      const before: Record<IdentityType, IdentityRead> = {
        aci: await readIdentity(context.store, 'aci'),
        pni: await readIdentity(context.store, 'pni'),
      };
      for (const type of IDENTITY_TYPES) {
        if (before[type].keyPair === null) {
          fail('the ' + type + ' key pair is absent before the reopen');
        }
      }
      const reopened = await context.reopen();
      for (const type of IDENTITY_TYPES) {
        assertEqual(
          await readIdentity(reopened, type),
          before[type],
          'the ' + type + ' identity after a reopen'
        );
      }
    },
  },
];
