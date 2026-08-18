/**
 * Wire types for the Convex relay adapter.
 *
 * The component isolates its tables. An application cannot read or query
 * them, only call the component's functions. Row types for those tables would
 * describe values no consumer can read, so this module declares none. See
 * `remote/relay/convex/component/schema.ts` for the storage layout and
 * `docs/SCHEMA.md` for what the relay stores, and for how long.
 *
 * What crosses the boundary is function arguments and return values, and those
 * types follow the component's own validators instead of repeating them.
 */

import type { FunctionReturnType } from 'convex/server';

import type { ConvexSignalProtocolRelayApi } from './relay';

/**
 * Prekey bundle returned by the `fetchPreKeyBundle` mutation.
 *
 * Derived from the component's return validator, so it cannot drift from what
 * the component actually emits. This type excludes `null`, which means no such
 * device, or no keys uploaded. The adapter's `fetchPreKeyBundle` returns `null`
 * in that case before it constructs a bundle.
 */
export type FetchedPreKeyBundle = NonNullable<
  FunctionReturnType<ConvexSignalProtocolRelayApi['keys']['fetchPreKeyBundle']>
>;
