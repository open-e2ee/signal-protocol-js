/**
 * The refusal of an identity at the trust gate, and the observer that hears
 * of each refusal.
 *
 * Each place that asks the trust decision (`SessionTrust.isTrusted`) and gets
 * `false` builds its `UntrustedIdentityError` here. So one observer hears of
 * every refusal of the session layer, on the send path and on the receive
 * path.
 *
 * @internal
 */

import type { IdentityType } from '../../keys/types';
import type { CompositeIdentityV1 } from '../../keys';
import { UntrustedIdentityError, type TrustDirection } from '../../types';
import type { ProtocolAddress } from '../../types/address';

/**
 * One identity that the trust gate refused.
 *
 * @internal
 */
export interface UntrustedIdentityRefusal {
  /** The device address that presented the identity. */
  readonly address: ProtocolAddress;
  /** The identity that the gate refused. */
  readonly identity: CompositeIdentityV1;
  /** The identity type that the gate checked. */
  readonly identityType: IdentityType;
  /** The direction that the gate checked. */
  readonly direction: TrustDirection;
}

/**
 * Hears of one refusal. The observer runs before the throw, so it must
 * return at once and must not throw. Queue any store read or app call.
 *
 * @internal
 */
export type UntrustedIdentityObserver = (refusal: UntrustedIdentityRefusal) => void;

/**
 * Tell `observer` of the refusal, and give the error to throw. A failure of
 * the observer does not change the refusal.
 *
 * @internal
 */
export function refuseUntrustedIdentity(
  observer: UntrustedIdentityObserver | undefined,
  refusal: UntrustedIdentityRefusal
): UntrustedIdentityError {
  try {
    observer?.(refusal);
  } catch {
    // The refusal is the security decision. A failed report cannot change it.
  }
  return new UntrustedIdentityError(refusal.address, refusal.identity);
}
