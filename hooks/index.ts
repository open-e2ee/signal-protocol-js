/**
 * Signal Protocol React Hooks
 *
 * This barrel exports all React hooks from the Signal Protocol library.
 * These are true React hooks (using useState, useEffect, etc.), distinct
 * from the event callback hooks in client/event-hooks.ts.
 *
 * @example
 * ```typescript
 * import { useKeyRotation, useConnectionPresence, useSingleFlight } from './';
 * ```
 */
export {};
export {
  useConnectionPresence,
  type UseConnectionPresenceOptions,
} from './use-connection-presence';
export { useSingleFlight } from './use-single-flight';
export {
  useKeyRotation,
  useKeyRotationWithControls,
  type UseKeyRotationOptions,
} from './use-key-rotation';
export {
  useSessionHealth,
  type UseSessionHealthOptions,
  type UseSessionHealthResult,
} from './use-session-health';
export type { SessionHealthResult } from '../client/types';
export {
  useGroupMembership,
  type UseGroupMembershipOptions,
  type UseGroupMembershipResult,
} from './use-group-membership';
