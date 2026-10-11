/**
 * The lifecycle of a retry request on the requester device.
 *
 * The request record of a failed envelope owns its retry request from the
 * first post to the answer or to a terminal state. A redelivery of the
 * failed envelope posts nothing while the record exists. A post that fails
 * with a retryable class is posted again by the scheduler at its next
 * attempt time. A post that fails with a conclusive class, the deadline of
 * the record, and an exhausted abuse allowance end the request. Each end
 * calls the `onRetryTerminal` hook once.
 */

import type { Logger } from '../logger';
import type { Envelope } from '../remote/relay/types';
import type { RetryRequest } from '../internal/sesame/types';
import {
  getRetryRequest,
  listRetryRequestIds,
  RETRY_REQUEST_DEADLINE_MS,
  storeRetryRequest,
  updateRetryRequest,
  withProcessedEnvelopeLock,
  type StoredRetryRequest,
} from '../local/store/reliability';
import { generateUuidV4 } from '../internal/crypto';
import { callHook, type SignalProtocolClientHooks } from './event-hooks';
import type { RetryFamilyReceive } from './retry-family';
import {
  postRetryRequest,
  postStoredRetryRequest,
  readRetryRequestEnvelope,
  type RetryPostOutcome,
  type RetryRequestDevice,
} from './retry-request-envelope';
import { rethrowRelayWorkStopped, type RelayWork, type RelayWorkTracker } from './relay-work';

type RetryRequestStore = Parameters<typeof storeRetryRequest>[0];

/**
 * What the retry request of one failed decrypt did.
 *
 * - `posted`, `pending`, `terminal`: as `postRetryRequest` gives them. A
 *   terminal request also called the hook.
 * - `owned`: the record of the failed envelope owns the request, so a
 *   redelivery of the failed envelope posted nothing.
 * - `deferred`: the rate limit refused a member, and the next attempt waits
 *   for the end of the limit window.
 * - `skipped`: nothing was posted or stored.
 */
export type RetryRequestOutcome = RetryPostOutcome | 'owned' | 'deferred' | 'skipped';

/**
 * Tell whether the receive path acknowledges a failed envelope after its
 * retry request. A failed envelope is acknowledged once a record owns its
 * request. A member is acknowledged only when its request attempt is posted
 * or ended, so a member that waits is delivered again.
 */
export function acknowledgesRetryRequest(outcome: RetryRequestOutcome, member: boolean): boolean {
  if (outcome === 'deferred' || outcome === 'skipped') return false;
  return !member || outcome === 'posted' || outcome === 'terminal';
}

/** What the requester uses to ask for a resend after one failed decrypt. */
export interface RetryRequestSource {
  readonly storage: RetryRequestStore;
  readonly logger: Required<Logger>;
  readonly hooks: SignalProtocolClientHooks | undefined;
  /** The local identity, which sends the request envelope. */
  readonly local: RetryRequestDevice;
  /** The user ID of the failed sender, for the log line of a refusal. */
  readonly senderUserId: string;
  /** Spends one request of the rate limit of the sender. False when refused. */
  allow(): boolean;
  /** The rate limit window, for the log line and the cooldown of a member. */
  readonly windowMs: number;
  /** Posts one request envelope. Without it, nothing is posted. */
  readonly send: ((envelope: Envelope) => Promise<unknown>) | undefined;
  /** Creates the request of a new attempt. */
  createRequest(): Promise<RetryRequest>;
  /** Arms the scheduler for the next attempt time or the deadline of a record. */
  readonly schedule: ((at: number) => void) | undefined;
}

/**
 * Call the `onRetryTerminal` hook for the terminal state of a request
 * record, once. It reads the record, calls the hook when the terminal state
 * is not emitted, and then stores it as emitted. A RelayWorkStopped from the
 * hook propagates and leaves the state not emitted, so the next scheduler
 * pass or redelivery calls the hook again.
 */
export async function emitRetryTerminal(
  storage: RetryRequestStore,
  hooks: SignalProtocolClientHooks | undefined,
  failedEnvelopeId: string
): Promise<void> {
  const record = await getRetryRequest(storage, failedEnvelopeId);
  const terminal = record?.terminal;
  if (!record || !terminal || terminal.emitted) return;
  await callHook(hooks, 'onRetryTerminal', { class: terminal.class, failedEnvelopeId });
  await updateRetryRequest(storage, failedEnvelopeId, record.retryId, record.attempt, {
    terminal: { ...terminal, emitted: true },
  });
}

/**
 * Ask for a resend after a failed decrypt, through the retry family of the
 * envelope.
 *
 * - A failed envelope with a record posts nothing and gives `owned`. It
 *   only calls the hook for a terminal state that is not emitted. The rate
 *   limit does not count it.
 * - A failed envelope with no record spends one request of the rate limit.
 *   A refusal stores a record that ends as `abuse-allowance-exhausted`.
 * - A member of a request that ended posts nothing and gives `terminal`.
 * - A member whose stored attempt is answered, or that has no record,
 *   spends one request of the rate limit, unless an earlier refusal set a
 *   next attempt time that has not come. A refusal sets that time to the
 *   end of the limit window and gives `deferred`.
 * - A member whose stored attempt is not answered posts it again, with no
 *   rate limit.
 *
 * After a post, a terminal outcome calls the hook, and any other outcome
 * arms the scheduler for the record.
 */
export async function requestRetryInFamily(
  family: RetryFamilyReceive,
  fingerprint: string | undefined,
  source: RetryRequestSource
): Promise<RetryRequestOutcome> {
  const { storage, logger, hooks } = source;
  const refused = (): void => {
    logger.warn('Retry rate limit exceeded for sender', {
      category: 'E2EE',
      data: { senderId: source.senderUserId, windowMs: source.windowMs },
    });
  };
  return family.requestRetry(fingerprint, async (failed) => {
    const failedEnvelopeId = failed.id;
    const { stored } = failed;
    if (failedEnvelopeId === undefined) {
      if (!source.allow()) {
        refused();
        return 'skipped';
      }
    } else if (failed.member === undefined) {
      if (stored) {
        await emitRetryTerminal(storage, hooks, failedEnvelopeId);
        return 'owned';
      }
      if (!source.allow()) {
        refused();
        const now = Date.now();
        await storeRetryRequest(storage, {
          failedEnvelopeId,
          retryId: await generateUuidV4(),
          attempt: 1,
          requestedAt: now,
          ...(failed.fingerprint !== undefined && { fingerprint: failed.fingerprint }),
          answered: false,
          deadlineAt: now + RETRY_REQUEST_DEADLINE_MS,
          terminal: { class: 'abuse-allowance-exhausted', at: now, emitted: false },
        });
        await emitRetryTerminal(storage, hooks, failedEnvelopeId);
        return 'terminal';
      }
    } else if (stored?.terminal) {
      await emitRetryTerminal(storage, hooks, failedEnvelopeId);
      return 'terminal';
    } else if (!stored || stored.answered) {
      const now = Date.now();
      if (stored?.lastFailureClass === 'rate-refusal' && (stored.nextAttemptAt ?? 0) > now) {
        return 'deferred';
      }
      if (!source.allow()) {
        refused();
        if (stored) {
          await updateRetryRequest(storage, failedEnvelopeId, stored.retryId, stored.attempt, {
            nextAttemptAt: now + source.windowMs,
            lastFailureClass: 'rate-refusal',
          });
        }
        return 'deferred';
      }
    }
    if (!source.send) {
      logger.warn('Cannot send retry request: no relay or callback', { category: 'E2EE' });
      return 'skipped';
    }
    const outcome = await postRetryRequest(
      storage,
      failed,
      () => source.createRequest(),
      source.local,
      source.send
    );
    if (failedEnvelopeId === undefined) return outcome;
    if (outcome === 'terminal') {
      await emitRetryTerminal(storage, hooks, failedEnvelopeId);
    } else {
      const record = await getRetryRequest(storage, failedEnvelopeId);
      if (record && !record.terminal) source.schedule?.(record.nextAttemptAt ?? record.deadlineAt);
    }
    return outcome;
  });
}

/** The longest delay that a timer takes. */
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

/**
 * The context of one scheduler pass: the hooks run through the relay work
 * of the pass. Without `send`, the pass only calls the hook for terminal
 * states.
 */
export interface RetryRequestPass {
  readonly storage: RetryRequestStore;
  readonly logger: Required<Logger>;
  readonly hooks: SignalProtocolClientHooks | undefined;
  readonly local: RetryRequestDevice;
  readonly send: ((envelope: Envelope) => Promise<unknown>) | undefined;
}

/**
 * Posts each stored retry request whose next attempt time has come, ends
 * each request at its deadline, and calls the hook for each terminal state
 * that is not emitted. A pass runs at start() and at the earliest next
 * attempt time or deadline of the records. Each pass is relay work, so a
 * client stop stops it. Each record is read and posted under the processed
 * lock of its failed envelope, as a receive does.
 *
 * @internal
 */
export class RetryRequestScheduler {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private armedAt = Infinity;
  private running: Promise<void> | undefined;
  private again = false;
  private stopped = true;

  constructor(
    private readonly relayWork: RelayWorkTracker,
    private readonly pass: (work: RelayWork) => RetryRequestPass
  ) {}

  /** Run a pass now, and arm the timer after it. The promise never rejects. */
  start(): Promise<void> {
    this.stopped = false;
    return this.run();
  }

  /** Clear the timer. No pass starts until the next start(). */
  stop(): void {
    this.stopped = true;
    this.clear();
  }

  /** Arm the timer for the given time when it is earlier than the armed time. */
  schedule(at: number): void {
    if (this.stopped || at >= this.armedAt) return;
    this.clear();
    this.armedAt = at;
    const delay = Math.min(MAX_TIMER_DELAY_MS, Math.max(0, at - Date.now()));
    const timer = setTimeout(() => {
      if (this.timer !== timer) return;
      this.timer = undefined;
      this.armedAt = Infinity;
      void this.run();
    }, delay);
    (timer as { unref?: () => void }).unref?.();
    this.timer = timer;
  }

  private clear(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.armedAt = Infinity;
  }

  /** Run a pass. A call during a pass runs one more pass after it. */
  private run(): Promise<void> {
    if (this.running) {
      this.again = true;
      return this.running;
    }
    const running = (async () => {
      do {
        this.again = false;
        if (this.stopped) return;
        // A pass logs its own failures. RelayWorkStopped ends the run.
        await this.relayWork.run((work) => this.runPass(work)).catch(() => undefined);
      } while (this.again);
    })().finally(() => {
      this.running = undefined;
    });
    this.running = running;
    return running;
  }

  private async runPass(work: RelayWork): Promise<void> {
    const pass = this.pass(work);
    const { storage, logger } = pass;
    let ids: string[];
    try {
      ids = await listRetryRequestIds(storage);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      logger.warn('The retry request scheduler failed to list the stored requests', {
        category: 'E2EE',
        data: { behavior: 'RETRY_REQUEST_SCHEDULE_FAILED', error: (error as Error).message },
      });
      return;
    }
    let next = Infinity;
    for (const failedEnvelopeId of ids) {
      work.proceed();
      try {
        const at = await withProcessedEnvelopeLock(storage, failedEnvelopeId, () =>
          this.passRecord(pass, failedEnvelopeId)
        );
        next = Math.min(next, at);
      } catch (error) {
        rethrowRelayWorkStopped(error);
        logger.warn('A stored retry request failed in the scheduler', {
          category: 'E2EE',
          data: {
            failedEnvelopeId,
            behavior: 'RETRY_REQUEST_SCHEDULE_FAILED',
            error: (error as Error).message,
          },
        });
      }
    }
    if (next !== Infinity) this.schedule(next);
  }

  /** Handle one record. It returns the time of the next pass for the record. */
  private async passRecord(pass: RetryRequestPass, failedEnvelopeId: string): Promise<number> {
    const { storage, hooks, send } = pass;
    const record = await getRetryRequest(storage, failedEnvelopeId);
    if (record?.terminal) {
      await emitRetryTerminal(storage, hooks, failedEnvelopeId);
      return Infinity;
    }
    if (!record || record.answered) return Infinity;
    if (!send) return Infinity;
    const now = Date.now();
    if (now >= record.deadlineAt) {
      await updateRetryRequest(storage, failedEnvelopeId, record.retryId, record.attempt, {
        terminal: { class: 'expired-content', at: now, emitted: false },
        nextAttemptAt: undefined,
      });
      await emitRetryTerminal(storage, hooks, failedEnvelopeId);
      return Infinity;
    }
    // With no next attempt time, the Relay holds the stored attempt.
    if (record.nextAttemptAt === undefined || record.nextAttemptAt > now) {
      return Math.min(record.nextAttemptAt ?? Infinity, record.deadlineAt);
    }
    const outcome = await postStoredRetryRequest(
      storage,
      record,
      () => storedRequest(record),
      pass.local,
      send
    );
    if (outcome === 'terminal') {
      await emitRetryTerminal(storage, hooks, failedEnvelopeId);
      return Infinity;
    }
    const after = await getRetryRequest(storage, failedEnvelopeId);
    if (!after || after.terminal || after.answered) return Infinity;
    return Math.min(after.nextAttemptAt ?? Infinity, after.deadlineAt);
  }
}

/**
 * The request of a new attempt for a stored record, from its stored
 * envelope, with the time of now. The scheduler has no failed envelope, so
 * it asks for the same message again.
 */
async function storedRequest(record: StoredRetryRequest): Promise<RetryRequest> {
  const envelope = record.envelope!;
  const read = readRetryRequestEnvelope(envelope, {
    userId: envelope.targetUserId,
    deviceId: envelope.targetDeviceId,
  });
  if (!read.ok) throw new Error(`The stored retry request does not decode: ${read.cause}`);
  return { ...read.request, timestamp: Date.now() };
}
