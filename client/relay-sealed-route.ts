/**
 * Relay sealed route: the anonymous route that a group endorsement takes for
 * one destination device.
 *
 * A group endorsement is bound to its exact set of recipient accounts. When
 * that set is one account, the Relay accepts the endorsement on its
 * direct sealed route, which stores one envelope for one device and writes
 * no group body. The cipher marks the endorsement of each single-device post
 * for that route. A shared group post is not marked, so it keeps the group
 * route even when it has one destination.
 *
 * A Relay that refuses the endorsement on the direct route as an unknown
 * authorization gets the post once more on the group route. The transport
 * marks the result of that post, so the cipher can record the fallback.
 *
 * No package entry exports this module. The marks are internal to the SDK,
 * so no public type carries them.
 *
 * @internal
 */

import type { SealedSenderAuth } from '../remote/relay/types';

type GroupSendAuth = Extract<SealedSenderAuth, { type: 'groupSendToken' }>;

const directEndorsements = new WeakSet<object>();
const groupRouteFallbacks = new WeakSet<object>();

/**
 * A copy of the endorsement of one destination device, marked for the
 * direct sealed route. The original object stays unmarked.
 */
export function forDirectSealedRoute(auth: GroupSendAuth): GroupSendAuth {
  const copy: GroupSendAuth = { ...auth };
  directEndorsements.add(copy);
  return copy;
}

/** True only for an endorsement object that `forDirectSealedRoute` returned. */
export function takesDirectSealedRoute(auth: SealedSenderAuth): boolean {
  return directEndorsements.has(auth);
}

/** Mark the result of a post that fell back to the group route. Returns the same result. */
export function markGroupRouteFallback<T extends object>(result: T): T {
  groupRouteFallbacks.add(result);
  return result;
}

/** True when the transport marked this result as a group-route fallback. */
export function usedGroupRouteFallback(result: unknown): boolean {
  return result !== null && typeof result === 'object' && groupRouteFallbacks.has(result);
}
