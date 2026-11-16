/**
 * The key transparency records in the local store metadata. Each key holds
 * the environment and the project scope of the connection, so the records
 * of one project log never apply to another.
 *
 * - `keyTransparency.head.v1:<environment>:<scope>`: the last verified head.
 * - `keyTransparency.selfCheck.v1:<environment>:<scope>`: the self-check
 *   schedule and health.
 * - `keyTransparency.lease.v1:<environment>:<scope>`: the lease of the client
 *   that runs the self-check, so that two clients on one store do not both
 *   run it.
 * - `keyTransparency.contactRechecks.v1:<environment>:<scope>`: the contact
 *   checks that wait for a recheck, so that a restart keeps them.
 *
 * Each write is a compare-and-set against the value that the writer read.
 * A record that does not decode reads as absent, and the next write
 * replaces it.
 */
import { base64ToBytes, bytesToUrlSafeBase64, urlSafeToBase64 } from '../../internal/crypto';
import type { KeyTransparencyFailureCode } from '../../internal/protocol/key-transparency/errors';
import { LOG_HASH_BYTES } from '../../internal/protocol/key-transparency/merkle';
import type { IdentityLogHead } from '../../internal/protocol/key-transparency/tree-head';
import type { Base64, SignalProtocolLocalStore } from '../../types';

/** The metadata methods that the records use. */
export type KeyTransparencyStore = Pick<
  SignalProtocolLocalStore,
  'getMetadata' | 'compareAndSetMetadata'
>;

/** The keys of the records of one project log. */
export interface KeyTransparencyRecordKeys {
  readonly head: string;
  readonly selfCheck: string;
  readonly lease: string;
  readonly contactRechecks: string;
}

/** Returns the record keys for an environment and a project scope. */
export function keyTransparencyRecordKeys(
  environment: string,
  scope: string
): KeyTransparencyRecordKeys {
  const suffix = `${environment}:${scope}`;
  return {
    head: `keyTransparency.head.v1:${suffix}`,
    selfCheck: `keyTransparency.selfCheck.v1:${suffix}`,
    lease: `keyTransparency.lease.v1:${suffix}`,
    contactRechecks: `keyTransparency.contactRechecks.v1:${suffix}`,
  };
}

/** A stored value and its raw text, which a later compare-and-set expects. */
export interface StoredRecord<T> {
  readonly raw: string | null;
  readonly value: T | undefined;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function object(raw: string | null): Record<string, unknown> | undefined {
  if (raw === null) return undefined;
  try {
    return asObject(JSON.parse(raw));
  } catch {
    return undefined;
  }
}

function time(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

// ---------------------------------------------------------------------------
// Last verified head
// ---------------------------------------------------------------------------

function decodeHead(raw: string | null): IdentityLogHead | undefined {
  const record = object(raw);
  if (
    record === undefined ||
    !time(record.treeSize) ||
    !time(record.timestamp) ||
    typeof record.root !== 'string'
  ) {
    return undefined;
  }
  let root: Uint8Array;
  try {
    root = base64ToBytes(urlSafeToBase64(record.root) as Base64);
  } catch {
    return undefined;
  }
  if (root.length !== LOG_HASH_BYTES) return undefined;
  return { treeSize: record.treeSize, root, timestamp: record.timestamp };
}

/** Reads the last verified head. */
export async function readVerifiedHead(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys
): Promise<StoredRecord<IdentityLogHead>> {
  const raw = await store.getMetadata(keys.head);
  return { raw, value: decodeHead(raw) };
}

/**
 * Replaces the last verified head when the store still has `expected`.
 * Returns false and writes nothing on a mismatch.
 */
export function writeVerifiedHead(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys,
  expected: string | null,
  head: IdentityLogHead
): Promise<boolean> {
  return store.compareAndSetMetadata(
    keys.head,
    expected,
    JSON.stringify({
      treeSize: head.treeSize,
      root: bytesToUrlSafeBase64(head.root),
      timestamp: head.timestamp,
    })
  );
}

// ---------------------------------------------------------------------------
// Self-check record
// ---------------------------------------------------------------------------

/**
 * The health of the self-check.
 *
 * - `unknown`: no self-check completed.
 * - `ok`: the last self-check that was not pending passed.
 * - `intermittent`: one failure since the last pass.
 * - `failing`: two or more consecutive failures, or an overdue append.
 */
export type SelfCheckHealth = 'unknown' | 'ok' | 'intermittent' | 'failing';

/** The kind of the last self-check outcome. */
export type SelfCheckOutcomeKind = 'pass' | 'not-logged' | 'failure' | 'unavailable';

/** The persisted self-check schedule and health. */
export interface SelfCheckRecord {
  /** The time of the next self-check, Unix milliseconds. */
  readonly nextCheckAt: number;
  readonly health: SelfCheckHealth;
  readonly lastOutcome?: {
    readonly at: number;
    readonly kind: SelfCheckOutcomeKind;
    readonly code?: KeyTransparencyFailureCode;
  };
  /** The time of the first result of the current run of pending appends. */
  readonly pendingSince?: number;
  /** The wait before the next check of a pending append. */
  readonly wait?: number;
}

const HEALTH = new Set<unknown>(['unknown', 'ok', 'intermittent', 'failing']);
const OUTCOME_KINDS = new Set<unknown>(['pass', 'not-logged', 'failure', 'unavailable']);

function decodeSelfCheck(raw: string | null): SelfCheckRecord | undefined {
  const record = object(raw);
  if (
    record === undefined ||
    !time(record.nextCheckAt) ||
    !HEALTH.has(record.health) ||
    (record.pendingSince !== undefined && !time(record.pendingSince)) ||
    (record.wait !== undefined && !time(record.wait))
  ) {
    return undefined;
  }
  const outcome = asObject(record.lastOutcome);
  const lastOutcome =
    outcome !== undefined &&
    time(outcome.at) &&
    OUTCOME_KINDS.has(outcome.kind) &&
    (outcome.code === undefined || typeof outcome.code === 'string')
      ? {
          at: outcome.at,
          kind: outcome.kind as SelfCheckOutcomeKind,
          ...(outcome.code === undefined
            ? {}
            : { code: outcome.code as KeyTransparencyFailureCode }),
        }
      : undefined;
  return {
    nextCheckAt: record.nextCheckAt,
    health: record.health as SelfCheckHealth,
    ...(lastOutcome === undefined ? {} : { lastOutcome }),
    ...(record.pendingSince === undefined ? {} : { pendingSince: record.pendingSince }),
    ...(record.wait === undefined ? {} : { wait: record.wait }),
  };
}

/** Reads the self-check record. */
export async function readSelfCheck(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys
): Promise<StoredRecord<SelfCheckRecord>> {
  const raw = await store.getMetadata(keys.selfCheck);
  return { raw, value: decodeSelfCheck(raw) };
}

/** Replaces the self-check record when the store still has `expected`. */
export function writeSelfCheck(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys,
  expected: string | null,
  record: SelfCheckRecord
): Promise<boolean> {
  return store.compareAndSetMetadata(keys.selfCheck, expected, JSON.stringify(record));
}

// ---------------------------------------------------------------------------
// Self-check lease
// ---------------------------------------------------------------------------

/** How long a lease holds when its holder does not release it. */
export const SELF_CHECK_LEASE_MILLISECONDS = 5 * 60 * 1_000;

/** A held lease. */
export interface SelfCheckLease {
  readonly raw: string;
}

/** The result of a lease claim. */
export type SelfCheckLeaseClaim =
  | { readonly kind: 'held'; readonly lease: SelfCheckLease }
  | { readonly kind: 'busy'; readonly until: number };

/**
 * Claims the lease for `holder` when no other holder has an unexpired lease.
 * A claim that loses a race to another client gives `busy`.
 */
export async function claimSelfCheckLease(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys,
  holder: string,
  now: number
): Promise<SelfCheckLeaseClaim> {
  const raw = await store.getMetadata(keys.lease);
  const current = object(raw);
  if (current !== undefined && time(current.until) && current.until > now) {
    return { kind: 'busy', until: current.until };
  }
  const until = now + SELF_CHECK_LEASE_MILLISECONDS;
  const claimed = JSON.stringify({ holder, until });
  return (await store.compareAndSetMetadata(keys.lease, raw, claimed))
    ? { kind: 'held', lease: { raw: claimed } }
    : { kind: 'busy', until };
}

/** Releases a held lease. A lease that another client took stays. */
export async function releaseSelfCheckLease(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys,
  lease: SelfCheckLease
): Promise<void> {
  await store.compareAndSetMetadata(keys.lease, lease.raw, null);
}

// ---------------------------------------------------------------------------
// Contact rechecks
// ---------------------------------------------------------------------------

/** The most contact rechecks that the record holds. */
export const MAXIMUM_CONTACT_RECHECKS = 256;

/** The recheck schedule of one contact pair. */
export interface ContactRecheckSchedule {
  /** The time of the next check, Unix milliseconds. */
  readonly nextCheckAt: number;
  /** 1 after one key mismatch or one not-logged result without a pending append. */
  readonly strikes: 0 | 1;
  /** The time of the first result of the current run of pending appends. */
  readonly pendingSince?: number;
  /** The wait before the next check of a pending append. */
  readonly wait?: number;
}

/** One persisted contact recheck. */
export interface ContactRecheckRecord extends ContactRecheckSchedule {
  readonly userId: string;
  /** The encoded contact identity. */
  readonly identity: Uint8Array;
}

function decodeContactRecheck(value: unknown): ContactRecheckRecord | undefined {
  const entry = asObject(value);
  if (
    entry === undefined ||
    typeof entry.userId !== 'string' ||
    typeof entry.identity !== 'string' ||
    !time(entry.nextCheckAt) ||
    (entry.strikes !== 0 && entry.strikes !== 1) ||
    (entry.pendingSince !== undefined && !time(entry.pendingSince)) ||
    (entry.wait !== undefined && !time(entry.wait))
  ) {
    return undefined;
  }
  let identity: Uint8Array;
  try {
    identity = base64ToBytes(urlSafeToBase64(entry.identity) as Base64);
  } catch {
    return undefined;
  }
  if (identity.length === 0) return undefined;
  return {
    userId: entry.userId,
    identity,
    nextCheckAt: entry.nextCheckAt,
    strikes: entry.strikes,
    ...(entry.pendingSince === undefined ? {} : { pendingSince: entry.pendingSince }),
    ...(entry.wait === undefined ? {} : { wait: entry.wait }),
  };
}

/**
 * Reads the contact rechecks. An entry that does not decode is left out. A
 * record without a `rechecks` list reads as absent.
 */
export async function readContactRechecks(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys
): Promise<StoredRecord<readonly ContactRecheckRecord[]>> {
  const raw = await store.getMetadata(keys.contactRechecks);
  const record = object(raw);
  if (record === undefined || !Array.isArray(record.rechecks)) return { raw, value: undefined };
  const value: ContactRecheckRecord[] = [];
  for (const entry of record.rechecks.slice(0, MAXIMUM_CONTACT_RECHECKS)) {
    const decoded = decodeContactRecheck(entry);
    if (decoded !== undefined) value.push(decoded);
  }
  return { raw, value };
}

/**
 * Replaces the contact rechecks when the store still has `expected`. An
 * empty list removes the record. A list longer than
 * `MAXIMUM_CONTACT_RECHECKS` throws `RangeError` and writes nothing.
 */
export function writeContactRechecks(
  store: KeyTransparencyStore,
  keys: KeyTransparencyRecordKeys,
  expected: string | null,
  rechecks: readonly ContactRecheckRecord[]
): Promise<boolean> {
  if (rechecks.length > MAXIMUM_CONTACT_RECHECKS) {
    return Promise.reject(new RangeError('Too many contact rechecks'));
  }
  return store.compareAndSetMetadata(
    keys.contactRechecks,
    expected,
    rechecks.length === 0
      ? null
      : JSON.stringify({
          rechecks: rechecks.map((recheck) => ({
            userId: recheck.userId,
            identity: bytesToUrlSafeBase64(recheck.identity),
            nextCheckAt: recheck.nextCheckAt,
            strikes: recheck.strikes,
            ...(recheck.pendingSince === undefined ? {} : { pendingSince: recheck.pendingSince }),
            ...(recheck.wait === undefined ? {} : { wait: recheck.wait }),
          })),
        })
  );
}
