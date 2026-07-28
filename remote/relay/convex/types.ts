/**
 * Wire types for the Convex relay adapter.
 *
 * The component's tables are isolated: an application cannot read or query
 * them, only call the component's functions. Row types for those tables would
 * describe values no consumer can obtain, so none are declared here — see
 * `remote/relay/convex/component/schema.ts` for the storage layout and
 * `docs/SCHEMA.md` for what is stored and for how long.
 *
 * What crosses the boundary is function arguments and return values, and those
 * are derived from the component's own validators rather than restated.
 */

import type { FunctionReturnType } from 'convex/server';

import type { ConvexSignalProtocolRelayApi } from './relay';

/**
 * Prekey bundle returned by the `fetchPreKeyBundle` mutation.
 *
 * Derived from the component's return validator, so it cannot drift from what
 * the component actually emits. `null` — no such device, or no keys uploaded —
 * is excluded; the adapter's `fetchPreKeyBundle` returns `null` in that case
 * before constructing a bundle.
 */
export type FetchedPreKeyBundle = NonNullable<
  FunctionReturnType<ConvexSignalProtocolRelayApi['keys']['fetchPreKeyBundle']>
>;
