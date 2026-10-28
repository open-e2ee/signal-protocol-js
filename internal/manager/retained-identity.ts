/** Existing permanent identities required by a retained client startup. */
import type { IdentityKeyPair, IdentityType } from '../../keys';
import type { SignalProtocolLocalStore } from '../../types';

/** @internal SDK-owned snapshots; never part of the hosted public result. */
export type RetainedIdentities = ReadonlyMap<IdentityType, IdentityKeyPair>;
/** @internal A failed existing-identity read never permits key generation. */
export class RetainedIdentityError extends Error {
  constructor(readonly reason: 'unavailable' | 'changed' | 'unreadable') {
    super(`The retained Signal identity is ${reason}.`);
  }
}
/** @internal Read without generating or returning material to an application. */
export async function readRetainedIdentities(
  storage: SignalProtocolLocalStore,
  types: readonly IdentityType[],
): Promise<RetainedIdentities> {
  const identities = new Map<IdentityType, IdentityKeyPair>();
  for (const type of types) {
    let value: IdentityKeyPair | null;
    try {
      value = await storage.getIdentityKey(type);
    } catch {
      throw new RetainedIdentityError('unreadable');
    }
    if (
      !value ||
      !value.dhKey ||
      !value.signingKey ||
      [
        value.dhKey.publicKey,
        value.dhKey.privateKey,
        value.signingKey.publicKey,
        value.signingKey.privateKey,
      ].some((key) => typeof key !== 'string' || key.length === 0) ||
      !Number.isSafeInteger(value.registrationId) ||
      value.registrationId < 1 ||
      value.registrationId > 16383
    ) {
      throw new RetainedIdentityError('unavailable');
    }
    // Own the comparison image even when an adapter returns a mutable object.
    identities.set(type, {
      dhKey: { ...value.dhKey },
      signingKey: { ...value.signingKey },
      registrationId: value.registrationId,
    });
  }
  return identities;
}
/** @internal Compare each original permanent key and registration identifier. */
export async function assertRetainedIdentity(
  storage: SignalProtocolLocalStore,
  type: IdentityType,
  expected: RetainedIdentities,
): Promise<void> {
  const original = expected.get(type);
  if (!original) throw new RetainedIdentityError('unavailable');
  const current = (await readRetainedIdentities(storage, [type])).get(type)!;
  if (
    current.registrationId !== original.registrationId ||
    current.dhKey.publicKey !== original.dhKey.publicKey ||
    current.dhKey.privateKey !== original.dhKey.privateKey ||
    current.signingKey.publicKey !== original.signingKey.publicKey ||
    current.signingKey.privateKey !== original.signingKey.privateKey
  ) {
    throw new RetainedIdentityError('changed');
  }
}
