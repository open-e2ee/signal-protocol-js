/**
 * The group fetcher of a client.
 *
 * The fetcher is the one path that brings a group's local state up to the
 * revision that authenticated group contexts claim. Receive and resend share
 * it, so they share one fetch budget for each group:
 *
 * - One fetch runs for a group at a time. A caller that needs the group while
 *   a fetch runs joins that fetch.
 * - A caller waits for a fetch up to a deadline. The fetch continues after the
 *   deadline, and its result still updates the group's receive record.
 * - A fetch that reaches the server head opens a 30 s window, also when the
 *   head is below the claim. Only a fetch that reaches no head, or a denial,
 *   doubles the window up to 1 h. Inside a window, the fetcher runs at most
 *   one fetch for each distinct claimed revision, up to
 *   `GROUP_FETCH_CLAIMS_PER_WINDOW`. A lying sender therefore delays an
 *   honest claim by one base window at most.
 * - Each message is decided on its own claim, not on the highest claim of
 *   the group. A sender that claims a revision the server never reaches
 *   therefore uses up only the fetch of that claim, and an honest claim
 *   above the head still gets its own fetch.
 * - A claim whose fetch ends below it is evaluated at the server head, as
 *   Signal evaluates a message against the state it could fetch, and the
 *   required revision becomes that head. A claim raised while the fetch ran
 *   stays the required revision when it is above that head. A claim above
 *   the head that no fetch in the window asked for is not evaluated at that
 *   head: it waits for a fetch.
 * - A verified refusal from the group server is a denial. It answers every
 *   claim known when its fetch started, and holds until a context claims a
 *   higher revision. A claim raised while the fetch ran is above it, so the
 *   next message with that claim fetches again.
 * - A fetch for a context that carries a signed group change first tries to
 *   apply that one change. It asks the group server only when the change
 *   does not apply or does not reach the claim. When the window has fetched
 *   its limit of claims, the change still applies, with no server call.
 * - start() resumes the groups that wait for a fetch, and one timer runs each
 *   group again when its window ends. The timer never fetches a group that
 *   the application blocks, as Signal never updates a blocked group.
 *
 * The fetch calls `syncGroup`, which takes the group's sender-key lock. The
 * fetcher must therefore never run inside that lock.
 */

import type { Logger } from '../logger';
import { GroupManager, type GroupStateStore } from '../internal/groups/manager';
import {
  GROUP_FETCH_WINDOW_MS,
  groupFetchBackoffMs,
  groupReceiveStatus,
  newGroupReceiveRecord,
  type GroupFetchDenial,
  type GroupReceiveRecord,
} from '../internal/groups/receive-record';
import type { DecryptedGroup } from '../internal/groups/types';

/** What the local state of a group supports now. */
export type GroupFreshness =
  | { kind: 'fresh'; revision: number }
  | { kind: 'denied'; reason: GroupFetchDenial }
  | {
      kind: 'unavailable';
      reason: 'update-pending' | 'update-failed';
      retryAfterMs: number;
    };

/** How long a caller waits for a fetch before it answers `update-pending`. */
export const GROUP_FETCH_DEADLINE_MS = 10_000;
/** The distinct claimed revisions that one window may fetch for a group. */
export const GROUP_FETCH_CLAIMS_PER_WINDOW = 16;
/**
 * The groups that one sender device's contexts may create and leave
 * unverified. It is a provisional resource bound.
 */
export const GROUP_UNVERIFIED_PER_SENDER_DEVICE = 100;

/** The sender device whose authenticated content carried a group context. */
export interface GroupContextSender {
  readonly senderId: string;
  readonly senderDeviceId: number;
}

type FetchOutcome =
  /** `server` is false for a carried change that applied with no fetch. */
  | { kind: 'synced'; head: number; state: DecryptedGroup; server: boolean }
  | { kind: 'denied'; reason: GroupFetchDenial; error: unknown }
  | { kind: 'failed'; error: unknown }
  /** A carried change that did not apply, where no server call was allowed. */
  | { kind: 'not-applied' };

/** An outcome that the receive record records. */
type RecordedOutcome = Exclude<FetchOutcome, { kind: 'not-applied' }>;

/** A fetch that runs for a group. */
interface InFlightFetch {
  /**
   * The required revision when the fetch started. A denial answers the
   * claims up to it, not the claims raised while the fetch ran.
   */
  readonly required: number;
  /**
   * The highest claim raised for the group while the fetch ran. The fetch
   * did not answer it, so the head that the fetch reaches does not lower it.
   */
  raised?: number;
  readonly outcome: Promise<FetchOutcome>;
}

/** The revision that one authenticated group context claims. */
export interface GroupRevisionClaim {
  /** The revision that the context claims. */
  readonly revision: number;
  /** The bytes of the signed change that the context carries, if any. */
  readonly change?: Uint8Array;
}

/** What the fetcher needs from its client. */
export interface GroupFetcherOptions {
  readonly store: GroupStateStore;
  /** Bring the group to the server head. It takes the sender-key lock. */
  readonly sync: (groupId: string) => Promise<DecryptedGroup>;
  /**
   * Apply a carried signed change. Null when the change does not apply, so
   * the fetch asks the group server.
   */
  readonly applyChange?: (
    groupId: string,
    revision: number,
    change: Uint8Array
  ) => Promise<DecryptedGroup | null>;
  /**
   * True for a group that the application blocks. The timer does not fetch
   * it. A hook that throws counts as blocked.
   */
  readonly isBlocked?: (groupId: string) => boolean | Promise<boolean>;
  /**
   * True while received content waits on the group. The receive queue owns
   * that content. A group with waiting content is never evicted, and the
   * timer fetches a stale group only while content waits. A hook that throws
   * counts as true.
   */
  readonly hasBlockedContent?: (groupId: string) => Promise<boolean>;
  /**
   * Called after a fetch records a synced or denied outcome, so that the
   * content that waits on the group is decided again. A failed fetch does
   * not call it, because the content still waits.
   */
  readonly onFetched?: (groupId: string) => void;
  /** Run one timer pass as tracked client work. */
  readonly runInBackground: (pass: () => Promise<void>) => Promise<void>;
  readonly logger: Required<Logger>;
  readonly now?: () => number;
  readonly deadlineMs?: number;
}

/** The denial that a group server refusal states, if it states one. */
export function groupFetchDenial(error: unknown): GroupFetchDenial | null {
  if (GroupManager.isNotReadableRejection(error)) return 'group-not-readable';
  const message = error instanceof Error ? error.message : '';
  if (message.startsWith('GROUP_NOT_FOUND:')) return 'group-not-found';
  if (message.startsWith('GROUP_ACCESS_REVOKED:')) return 'access-revoked';
  return null;
}

const TIMED_OUT = Symbol('timed out');

/** @internal */
export class GroupFetcher {
  private readonly inFlight = new Map<string, InFlightFetch>();
  private readonly due = new Map<string, number>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private timerDueAt = Number.POSITIVE_INFINITY;
  private running: Promise<void> | undefined;
  private stopped = true;
  private readonly now: () => number;
  private readonly deadlineMs: number;

  constructor(private readonly options: GroupFetcherOptions) {
    this.now = options.now ?? Date.now;
    this.deadlineMs = options.deadlineMs ?? GROUP_FETCH_DEADLINE_MS;
  }

  /**
   * Raise the group's required revision to a revision that an authenticated
   * group context claims. A claim never lowers it. Only a fetch that reaches
   * the server head does, and only to the highest claim raised while it ran.
   */
  async claim(groupId: string, revision: number): Promise<void> {
    await this.options.store.updateGroupReceiveRecord(groupId, (current) => {
      this.raiseInFlight(groupId, revision);
      const record = current ?? newGroupReceiveRecord('local');
      return revision > record.requiredRevision
        ? { ...record, requiredRevision: revision }
        : record;
    });
  }

  /**
   * Record a claim on the fetch that runs for the group, if one runs. It
   * runs inside the record update of the claim, so the fetch records its
   * outcome either before the claim or with the claim on its entry.
   */
  private raiseInFlight(groupId: string, revision: number): void {
    const running = this.inFlight.get(groupId);
    if (running) running.raised = Math.max(running.raised ?? revision, revision);
  }

  /**
   * Admit the master key and the claimed revision of an authenticated group
   * context.
   *
   * A known group only raises its required revision. A new group becomes an
   * unverified group of the sender device. When the device already has
   * `GROUP_UNVERIFIED_PER_SENDER_DEVICE` of them, the oldest one with no
   * blocked content is deleted first. When each of them has blocked content,
   * the new group is refused with `unverified-cap`. The record is written
   * before the master key, so a crash between the two leaves a record that
   * the next context completes.
   */
  async admitContext(
    groupId: string,
    masterKey: Uint8Array,
    revision: number,
    sender: GroupContextSender
  ): Promise<'admitted' | 'unverified-cap'> {
    const { store } = this.options;
    if (await store.getMasterKey(groupId)) {
      await this.claim(groupId, revision);
      return 'admitted';
    }
    if (!(await this.makeRoomFor(groupId, sender))) return 'unverified-cap';
    const createdAt = this.now();
    await store.updateGroupReceiveRecord(groupId, (current) => {
      this.raiseInFlight(groupId, revision);
      const record = current ?? newGroupReceiveRecord('context');
      return {
        ...record,
        requiredRevision: Math.max(record.requiredRevision, revision),
        unverified: record.unverified ?? {
          senderId: sender.senderId,
          senderDeviceId: sender.senderDeviceId,
          createdAt,
        },
      };
    });
    await store.storeMasterKey(groupId, masterKey);
    return 'admitted';
  }

  /**
   * Delete the sender device's oldest unverified groups with no blocked
   * content until a new one fits under the cap. False when none can go.
   */
  private async makeRoomFor(
    groupId: string,
    sender: GroupContextSender
  ): Promise<boolean> {
    const { store } = this.options;
    const own: Array<{ groupId: string; record: GroupReceiveRecord }> = [];
    for (const id of await store.listGroupReceiveRecords()) {
      if (id === groupId) continue;
      const record = await store.getGroupReceiveRecord(id);
      if (
        record?.unverified?.senderId === sender.senderId &&
        record.unverified.senderDeviceId === sender.senderDeviceId
      ) {
        own.push({ groupId: id, record });
      }
    }
    let excess = own.length - GROUP_UNVERIFIED_PER_SENDER_DEVICE + 1;
    if (excess <= 0) return true;
    own.sort((a, b) => a.record.unverified!.createdAt - b.record.unverified!.createdAt);
    for (const candidate of own) {
      if (excess <= 0) break;
      if (this.inFlight.has(candidate.groupId)) continue;
      if (await this.hasBlockedContent(candidate.groupId)) continue;
      // Verified state clears `unverified`, so the check repeats inside the
      // atomic update. Content that blocks on the group after the check
      // admits the group again from its own context when it is decided.
      const kept = await store.updateGroupReceiveRecord(candidate.groupId, (current) =>
        current?.unverified ? null : current
      );
      if (kept === null) {
        this.due.delete(candidate.groupId);
        excess--;
      }
    }
    return excess <= 0;
  }

  /**
   * Answer whether the local state of the group is fresh enough to evaluate,
   * and fetch first when the budget allows it.
   *
   * @param claim - The claim of the message under evaluation. Without one,
   *   the group's required revision is the claim. A fetch tries a carried
   *   change before it asks the group server.
   */
  async ensureFresh(
    groupId: string,
    claim?: GroupRevisionClaim
  ): Promise<GroupFreshness> {
    // A fetch that another caller started can make the group fresh, so the
    // caller joins it and decides again. Three rounds bound the joins.
    for (let round = 0; round < 3; round++) {
      const running = this.inFlight.get(groupId);
      if (running) {
        if ((await this.withDeadline(running.outcome)) === TIMED_OUT) {
          return this.pending();
        }
        continue;
      }
      const decision = await this.decide(groupId, claim);
      if (decision.kind !== 'fetch' && decision.kind !== 'apply') return decision;
      if (this.inFlight.has(groupId)) continue;
      const outcome = await this.withDeadline(
        this.fetch(
          groupId,
          decision.target,
          decision.required,
          claim,
          decision.kind === 'fetch'
        ).outcome
      );
      if (outcome === TIMED_OUT) return this.pending();
      if (outcome.kind === 'not-applied') {
        return decision.kind === 'apply' ? decision.wait : this.pending();
      }
      if (outcome.kind === 'denied') return { kind: 'denied', reason: outcome.reason };
      if (outcome.kind === 'failed') {
        const record = await this.options.store.getGroupReceiveRecord(groupId);
        return {
          kind: 'unavailable',
          reason: 'update-failed',
          retryAfterMs: Math.max(0, (record?.init.nextAttemptAt ?? 0) - this.now()),
        };
      }
      return { kind: 'fresh', revision: outcome.head };
    }
    return this.pending();
  }

  /**
   * Run a manual sync of the group. It joins a fetch in flight, or runs
   * one that the receive record then records. It returns the result of a
   * fetch only when that fetch called the group server. After a fetch that
   * only applied a carried change, or applied none, it waits for the next
   * fetch, its own when no other caller starts one first. It rejects as
   * the sync rejects.
   */
  async sync(groupId: string): Promise<DecryptedGroup> {
    for (;;) {
      let running = this.inFlight.get(groupId);
      if (!running) {
        const record = await this.options.store.getGroupReceiveRecord(groupId);
        const required = record?.requiredRevision ?? 0;
        running = this.inFlight.get(groupId) ?? this.fetch(groupId, required, required);
      }
      const outcome = await running.outcome;
      // A carried change can end a fetch with no server call. Only a
      // server call ends in a denial or a failure.
      if (outcome.kind === 'not-applied') continue;
      if (outcome.kind === 'synced') {
        if (outcome.server) return outcome.state;
        continue;
      }
      throw outcome.error;
    }
  }

  /** Schedule the groups that wait for a fetch, and arm the timer. */
  async start(): Promise<void> {
    this.stopped = false;
    const now = this.now();
    for (const groupId of await this.options.store.listGroupReceiveRecords()) {
      const dueAt = await this.dueAt(groupId, now);
      if (dueAt !== null) this.due.set(groupId, dueAt);
    }
    this.arm();
  }

  /** Clear the timer. A fetch in flight finishes and records its result. */
  stop(): void {
    this.stopped = true;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.timerDueAt = Number.POSITIVE_INFINITY;
  }

  private pending(): GroupFreshness {
    return {
      kind: 'unavailable',
      reason: 'update-pending',
      retryAfterMs: this.deadlineMs,
    };
  }

  private async decide(
    groupId: string,
    claim: GroupRevisionClaim | undefined
  ): Promise<
    | GroupFreshness
    | { kind: 'fetch'; target: number; required: number }
    | { kind: 'apply'; target: number; required: number; wait: GroupFreshness }
  > {
    const { store } = this.options;
    const [record, state] = await Promise.all([
      store.getGroupReceiveRecord(groupId),
      store.getGroupState(groupId),
    ]);
    const revision = state?.revision ?? null;
    if (groupReceiveStatus(record, revision) === 'denied') {
      return { kind: 'denied', reason: record!.init.denied!.reason };
    }
    // The budget key is the claim of the message under evaluation. The
    // required revision is the highest claim of any sender, so one false
    // claim would otherwise stand in for every later honest one (A6). A
    // fetch can lower the required revision below this claim, so the claim
    // is compared with the state, not the derived status.
    const required = record?.requiredRevision ?? 0;
    const target = claim?.revision ?? required;
    if (revision !== null && revision >= target) return { kind: 'fresh', revision };
    const init = record?.init;
    const now = this.now();
    if (init && now < init.nextAttemptAt) {
      const claims = init.fetchedClaims ?? [];
      const waitForWindow: GroupFreshness = {
        kind: 'unavailable',
        reason: 'update-failed',
        retryAfterMs: init.nextAttemptAt - now,
      };
      if (claims.includes(target)) {
        // This claim was fetched in this window. A group whose state is at
        // the head that the fetch reached is evaluated at that head.
        if (revision !== null && init.head !== undefined && revision >= init.head) {
          return { kind: 'fresh', revision };
        }
        return waitForWindow;
      }
      // No fetch in this window asked for this claim, so the head that the
      // window reached says nothing about it. A carried change needs no
      // server call, so it still applies when the window is full (C7).
      if (claims.length >= GROUP_FETCH_CLAIMS_PER_WINDOW) {
        return claim?.change && this.options.applyChange
          ? { kind: 'apply', target, required, wait: waitForWindow }
          : waitForWindow;
      }
    }
    return { kind: 'fetch', target, required };
  }

  /**
   * Start a fetch that brings the group to `target`. `required` is the
   * group's required revision that the caller read. With `serverCall`
   * false, only a carried change can, and the window's fetch budget is not
   * used. The caller joins a fetch that runs instead of starting one.
   */
  private fetch(
    groupId: string,
    target: number,
    required: number,
    claim?: GroupRevisionClaim,
    serverCall = true
  ): InFlightFetch {
    const entry: { readonly required: number; raised?: number } = { required };
    const fetching = (async (): Promise<FetchOutcome> => {
      let outcome: RecordedOutcome;
      try {
        const change = claim?.change;
        const applied =
          claim && change && this.options.applyChange
            ? await this.options
                .applyChange(groupId, claim.revision, change)
                .catch(() => null)
            : null;
        if (applied && applied.revision >= target) {
          outcome = { kind: 'synced', head: applied.revision, state: applied, server: false };
        } else if (!serverCall) {
          return { kind: 'not-applied' };
        } else {
          const state = await this.options.sync(groupId);
          outcome = { kind: 'synced', head: state.revision, state, server: true };
        }
      } catch (error) {
        const denial = groupFetchDenial(error);
        outcome = denial
          ? { kind: 'denied', reason: denial, error }
          : { kind: 'failed', error };
      }
      try {
        const record = await this.options.store.updateGroupReceiveRecord(
          groupId,
          (current) => this.recordOutcome(current, target, outcome, serverCall, entry)
        );
        this.reschedule(groupId, record);
        if (outcome.kind !== 'failed') this.options.onFetched?.(groupId);
      } catch (error) {
        this.options.logger.warn('The group fetcher failed to record a fetch', {
          category: 'E2EE',
          data: { behavior: 'GROUP_FETCH_RECORD_FAILED', error: (error as Error).message },
        });
      }
      if (outcome.kind === 'failed') {
        this.options.logger.warn('A group fetch failed', {
          category: 'E2EE',
          data: {
            behavior: 'GROUP_FETCH_FAILED',
            error: (outcome.error as Error)?.message,
          },
        });
      }
      return outcome;
    })().finally(() => {
      this.inFlight.delete(groupId);
    });
    const running = Object.assign(entry, { outcome: fetching });
    this.inFlight.set(groupId, running);
    return running;
  }

  /**
   * The receive record after one fetch for `target`. A fetch outside the
   * budget leaves the window and its claims as they are.
   */
  private recordOutcome(
    current: GroupReceiveRecord | null,
    target: number,
    outcome: RecordedOutcome,
    budgeted: boolean,
    { required, raised }: Pick<InFlightFetch, 'required' | 'raised'>
  ): GroupReceiveRecord {
    const record = current ?? newGroupReceiveRecord('local');
    const now = this.now();
    const claims =
      now < record.init.nextAttemptAt ? [...(record.init.fetchedClaims ?? [])] : [];
    if (!claims.includes(target)) claims.push(target);
    const failed = (attempts: number) => ({
      attempts,
      nextAttemptAt: now + groupFetchBackoffMs(attempts),
      // A failed fetch reached no head, so no claim in the window can be
      // evaluated at the head of an earlier fetch.
      fetchedClaims: claims,
    });
    switch (outcome.kind) {
      case 'synced': {
        const { unverified: _verified, ...verified } = record;
        // A fetch that reaches the server head is complete, also below the
        // claim. The required revision becomes that head, so a claim that the
        // server never reaches holds the group stale no longer (C7). A claim
        // raised while the fetch ran can name a revision that the server
        // reached after it answered, so it stays. A carried change says
        // nothing about the server head.
        const requiredRevision = outcome.server
          ? Math.max(outcome.head, raised ?? outcome.head)
          : record.requiredRevision;
        if (!budgeted) return { ...verified, requiredRevision };
        return {
          ...verified,
          requiredRevision,
          init: {
            attempts: 0,
            nextAttemptAt: now + GROUP_FETCH_WINDOW_MS,
            head: outcome.head,
            fetchedClaims: claims,
          },
        };
      }
      case 'denied':
        // A verified refusal answers every claim known when the fetch
        // started, so it holds up to the highest one, not only up to the
        // claim of this fetch. A claim raised while the fetch ran can come
        // from a change that the refusal did not see, so it stays above.
        return {
          ...record,
          init: {
            ...failed(record.init.attempts + 1),
            denied: {
              atRevision: Math.max(target, required),
              reason: outcome.reason,
            },
          },
        };
      case 'failed':
        return {
          ...record,
          init: {
            ...failed(record.init.attempts + 1),
            ...(record.init.denied ? { denied: record.init.denied } : {}),
          },
        };
    }
  }

  /** When the timer must fetch the group again, or null when it must not. */
  private async dueAt(groupId: string, now: number): Promise<number | null> {
    const { store } = this.options;
    const [record, state, key] = await Promise.all([
      store.getGroupReceiveRecord(groupId),
      store.getGroupState(groupId),
      store.getMasterKey(groupId),
    ]);
    // A record written before its master key has nothing to fetch with.
    if (!record || !key || (await this.isBlocked(groupId))) return null;
    return this.dueFor(groupId, record, state?.revision ?? null, now);
  }

  /** Whether the application blocks the group. A failed answer blocks it. */
  private async isBlocked(groupId: string): Promise<boolean> {
    try {
      return (await this.options.isBlocked?.(groupId)) ?? false;
    } catch (error) {
      this.options.logger.warn('The group block check failed, so the timer skips the group', {
        category: 'E2EE',
        data: {
          behavior: 'GROUP_FETCH_BLOCK_CHECK_FAILED',
          error: error instanceof Error ? error.message : String(error),
        },
      });
      return true;
    }
  }

  /** Whether received content waits on the group. A failed answer keeps it. */
  private async hasBlockedContent(groupId: string): Promise<boolean> {
    try {
      return (await this.options.hasBlockedContent?.(groupId)) ?? false;
    } catch (error) {
      this.options.logger.warn('The blocked content check failed, so the group is kept', {
        category: 'E2EE',
        data: {
          behavior: 'GROUP_FETCH_CONTENT_CHECK_FAILED',
          error: error instanceof Error ? error.message : String(error),
        },
      });
      return true;
    }
  }

  private async dueFor(
    groupId: string,
    record: GroupReceiveRecord,
    revision: number | null,
    now: number
  ): Promise<number | null> {
    const status = groupReceiveStatus(record, revision);
    if (status === 'ready' || status === 'denied') return null;
    // A stale group with no content waiting on it waits for the next claim.
    if (status === 'stale' && !(await this.hasBlockedContent(groupId))) return null;
    return Math.max(now, record.init.nextAttemptAt);
  }

  private reschedule(groupId: string, record: GroupReceiveRecord | null): void {
    if (this.stopped || !record) {
      this.due.delete(groupId);
      return;
    }
    void this.options.store
      .getGroupState(groupId)
      .then((state) => this.dueFor(groupId, record, state?.revision ?? null, this.now()))
      .then((dueAt) => {
        if (dueAt === null) this.due.delete(groupId);
        else this.due.set(groupId, dueAt);
        this.arm();
      })
      .catch(() => undefined);
  }

  /** Arm the one timer at the earliest due group. */
  private arm(): void {
    if (this.stopped || this.running) return;
    let next = Number.POSITIVE_INFINITY;
    for (const dueAt of this.due.values()) next = Math.min(next, dueAt);
    if (next === this.timerDueAt) return;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.timerDueAt = next;
    if (next === Number.POSITIVE_INFINITY) return;
    const timer = setTimeout(() => {
      if (this.timer !== timer) return;
      this.timer = undefined;
      this.timerDueAt = Number.POSITIVE_INFINITY;
      void this.runDue();
    }, Math.max(0, next - this.now()));
    (timer as { unref?: () => void }).unref?.();
    this.timer = timer;
  }

  /** Fetch each due group in turn, then arm the timer again. */
  private runDue(): Promise<void> {
    if (this.running) return this.running;
    const running = this.options
      .runInBackground(async () => {
        const now = this.now();
        const ready = [...this.due].filter(([, dueAt]) => dueAt <= now);
        for (const [groupId] of ready) {
          if (this.stopped) return;
          this.due.delete(groupId);
          if (await this.isBlocked(groupId)) continue;
          await this.ensureFresh(groupId);
          // A pass that did not fetch leaves the group for the next window.
          const dueAt = this.inFlight.has(groupId)
            ? null
            : await this.dueAt(groupId, this.now());
          if (dueAt !== null && dueAt > now) this.due.set(groupId, dueAt);
        }
      })
      .catch(() => undefined)
      .finally(() => {
        this.running = undefined;
        this.arm();
      });
    this.running = running;
    return running;
  }

  private async withDeadline<T>(promise: Promise<T>): Promise<T | typeof TIMED_OUT> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMED_OUT), this.deadlineMs);
      (timer as { unref?: () => void }).unref?.();
    });
    try {
      return await Promise.race([promise, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }
}
