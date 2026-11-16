/**
 * The verification state sync from another device of the own account: the
 * rule that applies it to the pinned identity of a contact.
 *
 * The client applies a sync only to the identity that it pinned. `verified`
 * marks that identity verified. `default` clears its verification. The
 * client ignores a sync for the own account, for a contact with no pinned
 * identity, or for an identity that is not the pinned identity, and logs
 * `VERIFICATION_STATE_SYNC_NOT_APPLIED` with the reason. A sync never pins
 * or rotates an identity. The application still gets the sync content.
 */

import type { Logger } from '../logger';
import { base64ToBytes } from '../internal/crypto';
import type { CompositeIdentityV1 } from '../keys/types';
import { decodeCompositeIdentityV1, evaluateContactIdentityCandidate } from '../keys/identity';
import { ProtocolAddress } from '../types/address';
import type { IdentityKeyStore } from '../types/api';
import type { Base64 } from '../types/utils';
import type { ParsedSyncContent } from './content-adapter';

/**
 * The reason that the client did not apply a verification state sync.
 *
 * @internal
 */
export type VerificationStateSyncNotAppliedReason =
  | 'malformed-sync'
  | 'own-account'
  | 'malformed-identity-key'
  | 'unknown-recipient'
  | 'identity-mismatch'
  | 'unverify-unsupported'
  | 'store-refused';

/** @internal */
export interface ApplyVerificationStateSyncOptions {
  readonly storage: Pick<
    IdentityKeyStore,
    'getContactIdentity' | 'verifyContactIdentity' | 'unverifyContactIdentity'
  >;
  readonly ownUserId: string;
  /** The user ID of the device that sent the sync. */
  readonly senderUserId: string;
  readonly sync: ParsedSyncContent | null | undefined;
  readonly logger: Required<Logger>;
}

function decodeIdentityKey(identityKey: string): CompositeIdentityV1 | null {
  try {
    return decodeCompositeIdentityV1(base64ToBytes(identityKey as Base64));
  } catch {
    return null;
  }
}

/**
 * Apply a verification state sync to the pinned identity of its target.
 * Content that is not a verification state sync is not changed. The commit
 * already refused a sync from another account. This function also ignores
 * one, as a second check.
 *
 * @internal
 */
export async function applyVerificationStateSync(
  options: ApplyVerificationStateSyncOptions
): Promise<void> {
  const { storage, ownUserId, senderUserId, sync, logger } = options;
  if (sync?.type !== 'verificationState' || senderUserId !== ownUserId) return;
  const notApplied = (reason: VerificationStateSyncNotAppliedReason, targetUserId?: string) => {
    logger.warn('A verification state sync was not applied', {
      category: 'SECURITY',
      data: {
        behavior: 'VERIFICATION_STATE_SYNC_NOT_APPLIED',
        reason,
        ...(targetUserId !== undefined && { targetUserId }),
      },
    });
  };
  const state = sync.verificationState;
  if (!state) return notApplied('malformed-sync');
  const { targetUserId } = state;
  if (targetUserId === ownUserId) return notApplied('own-account', targetUserId);
  const identity = decodeIdentityKey(state.identityKey);
  if (!identity) return notApplied('malformed-identity-key', targetUserId);

  // The trust address of a contact, as `confirmSafetyNumber` uses.
  const address = ProtocolAddress.create(targetUserId, 1);
  try {
    const pinned = await storage.getContactIdentity(address, 'aci');
    if (!pinned) return notApplied('unknown-recipient', targetUserId);
    if (evaluateContactIdentityCandidate(pinned, identity) !== 'MATCH') {
      return notApplied('identity-mismatch', targetUserId);
    }
    if (state.state === 'verified') {
      if (pinned.trustState === 'VERIFIED') return;
      await storage.verifyContactIdentity(address, identity, 'aci');
      return;
    }
    if (pinned.trustState !== 'VERIFIED') return;
    if (typeof storage.unverifyContactIdentity !== 'function') {
      return notApplied('unverify-unsupported', targetUserId);
    }
    await storage.unverifyContactIdentity(address, identity, 'aci');
  } catch {
    notApplied('store-refused', targetUserId);
  }
}
