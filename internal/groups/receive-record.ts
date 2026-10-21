/**
 * The receive record of a group: what a device must verify before it delivers
 * the group's content.
 *
 * The record sits beside the master key and the cached state. Its required
 * revision is the revision that local state must reach before the device
 * delivers. Its fetch state bounds the server work that claims can cause.
 */

export {};

/**
 * How the device learned the group's master key.
 *
 * No SDK path writes `'provisioning'`.
 */
export type GroupRecordSource = 'provisioning' | 'context' | 'sync' | 'local';

/** A verified answer from the group server that refuses this device. */
export type GroupFetchDenial =
  | 'group-not-found'
  | 'access-revoked'
  | 'group-not-readable';

/** The fetch backoff and the last verified denial of one group. */
export interface GroupFetchState {
  /**
   * Consecutive fetches that reached no head, or that the server denied.
   * Zero after a fetch reaches the server head.
   */
  attempts: number;
  /** The end of the current backoff window, in epoch milliseconds. */
  nextAttemptAt: number;
  /** The server head that the last fetch reached. A failed fetch clears it. */
  head?: number;
  /** The claimed revisions already fetched in the current window. */
  fetchedClaims?: number[];
  /**
   * The last verified denial, and the highest claim it answered: the claim
   * of its fetch or the required revision then, whichever is higher.
   */
  denied?: { atRevision: number; reason: GroupFetchDenial };
}

/** The sender device whose group context created an unverified group. */
export interface GroupUnverifiedOrigin {
  senderId: string;
  senderDeviceId: number;
  createdAt: number;
}

/** The receive record of one group. */
export interface GroupReceiveRecord {
  /**
   * The highest revision that an authenticated group context from any
   * sender claimed since the last fetch that reached the server head. That
   * fetch sets it to the head, so a claim above the head holds the group
   * stale only until the fetch for it. Local state below it is stale.
   */
  requiredRevision: number;
  source: GroupRecordSource;
  init: GroupFetchState;
  /** Set while a group that a sender's context created has never verified. */
  unverified?: GroupUnverifiedOrigin;
}

/** The status that a receive record and the local state derive. */
export type GroupReceiveStatus = 'ready' | 'stale' | 'pending' | 'denied';

/** The minimum time between two fetches of one group. */
export const GROUP_FETCH_WINDOW_MS = 30_000;
/** The maximum backoff after repeated fetch failures. */
export const GROUP_FETCH_MAX_BACKOFF_MS = 60 * 60_000;

/** A receive record for a group with no claims and no fetch history. */
export function newGroupReceiveRecord(
  source: GroupRecordSource
): GroupReceiveRecord {
  return {
    requiredRevision: 0,
    source,
    init: { attempts: 0, nextAttemptAt: 0 },
  };
}

/** A deep copy of a receive record, which holds only JSON values. */
export function cloneGroupReceiveRecord(
  record: GroupReceiveRecord
): GroupReceiveRecord {
  return JSON.parse(JSON.stringify(record)) as GroupReceiveRecord;
}

/**
 * The derived status of a group.
 *
 * A denial holds only while no claim above the revision it answered exists.
 */
export function groupReceiveStatus(
  record: GroupReceiveRecord | null,
  stateRevision: number | null
): GroupReceiveStatus {
  const required = record?.requiredRevision ?? 0;
  const denied = record?.init.denied;
  if (denied && denied.atRevision >= required) return 'denied';
  if (stateRevision === null) return 'pending';
  return stateRevision >= required ? 'ready' : 'stale';
}

/** The backoff delay after `attempts` consecutive failures. */
export function groupFetchBackoffMs(attempts: number): number {
  return Math.min(
    GROUP_FETCH_WINDOW_MS * 2 ** Math.max(0, attempts),
    GROUP_FETCH_MAX_BACKOFF_MS
  );
}
