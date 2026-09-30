/**
 * Bounded fan-out: parallel protocol work whose relay requests share one
 * bound.
 *
 * A client owns one BoundedFanOut. Every fan-out of the client sends its relay
 * requests through request(), so the client has at most `limit` relay requests
 * in flight in total, also when one fan-out runs inside another.
 *
 * A slot is held only while one relay request runs. The request function must
 * not await a lock or another request(): four callers that hold every slot and
 * wait for a fifth slot never continue. The lock order is: session lock, then
 * user lock, then a slot.
 *
 * all() runs one phase: a task for each item, all at the same time. It settles
 * only after every item settles, so it is a barrier. phases() runs protocol
 * phases in order, and a phase starts only after the phase before it
 * succeeded.
 *
 * A stop signal ends the work: after it aborts, no request starts and no phase
 * starts. A request in flight runs on. The work rejects with the error of the
 * `stopped` option.
 */

/** Relay requests that one client has in flight at most. */
export const RELAY_REQUESTS_IN_FLIGHT = 4;

/** The options of a BoundedFanOut. */
export interface BoundedFanOutOptions {
  /** Relay requests in flight at most. Default: RELAY_REQUESTS_IN_FLIGHT */
  limit?: number;
  /** The error for work that a stop signal ended. */
  stopped: () => Error;
}

/** The outcome of one item of a fan-out. */
export type FanOutOutcome<R> =
  | { readonly ok: true; readonly value: R }
  | { readonly ok: false; readonly error: unknown };

/**
 * One or more items of a fan-out failed. Every item settled before this error.
 */
export class FanOutError<R = unknown> extends Error {
  /** The error of each failed item, in input order. */
  readonly errors: readonly unknown[];

  /** The outcome of each item, in input order. */
  readonly outcomes: readonly FanOutOutcome<R>[];

  constructor(outcomes: readonly FanOutOutcome<R>[]) {
    const errors = outcomes.flatMap((outcome) => (outcome.ok ? [] : [outcome.error]));
    const first = errors[0];
    const detail = first instanceof Error ? first.message : String(first);
    super(`${errors.length} of ${outcomes.length} fan-out items failed: ${detail}`);
    this.name = 'FanOutError';
    this.errors = errors;
    this.outcomes = outcomes;
  }
}

/**
 * The error of the first failed item of a fan-out, in input order, so a
 * caller sees the error that the same work in input order threw. Any other
 * error is returned as it is.
 */
export function firstItemError(error: unknown): unknown {
  return error instanceof FanOutError ? error.errors[0] : error;
}

/**
 * The relay request bound of one client, and the fan-outs that share it.
 */
export class BoundedFanOut {
  readonly limit: number;
  private readonly stopped: () => Error;
  private inFlight = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(options: BoundedFanOutOptions) {
    const limit = options.limit ?? RELAY_REQUESTS_IN_FLIGHT;
    if (!Number.isInteger(limit) || limit < 1) {
      throw new RangeError(`The fan-out limit must be a positive integer, not ${limit}`);
    }
    this.limit = limit;
    this.stopped = options.stopped;
  }

  /**
   * Send one relay request under a slot. The slot is released when the request
   * settles. When the stop signal aborts before the request gets a slot, the
   * request never starts.
   */
  async request<T>(send: () => Promise<T>, stopSignal?: AbortSignal): Promise<T> {
    await this.acquire(stopSignal);
    try {
      return await send();
    } finally {
      this.release();
    }
  }

  /**
   * Run task for each item at the same time. Results keep input order. A failed
   * item does not stop the other items. After every item settles, a failure
   * rejects with a FanOutError, and a stop rejects with the `stopped` error.
   * The fan-out holds no slot: each task takes a slot for each request.
   */
  async all<T, R>(
    items: readonly T[],
    task: (item: T, index: number) => Promise<R>,
    stopSignal?: AbortSignal
  ): Promise<R[]> {
    if (stopSignal?.aborted) throw this.stopped();
    const outcomes = await Promise.all(
      items.map((item, index) =>
        new Promise<R>((resolve) => resolve(task(item, index))).then(
          (value): FanOutOutcome<R> => ({ ok: true, value }),
          (error: unknown): FanOutOutcome<R> => ({ ok: false, error })
        )
      )
    );
    const values: R[] = [];
    for (const outcome of outcomes) {
      if (!outcome.ok) {
        if (stopSignal?.aborted) throw this.stopped();
        throw new FanOutError(outcomes);
      }
      values.push(outcome.value);
    }
    return values;
  }

  /** Protocol phases that share one stop signal. */
  phases(stopSignal?: AbortSignal): FanOutPhases {
    return new FanOutPhases(this, this.stopped, stopSignal);
  }

  private acquire(stopSignal?: AbortSignal): Promise<void> {
    if (stopSignal?.aborted) return Promise.reject(this.stopped());
    if (this.inFlight < this.limit) {
      this.inFlight++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const grant = () => {
        stopSignal?.removeEventListener('abort', abandon);
        resolve();
      };
      const abandon = () => {
        const index = this.waiting.indexOf(grant);
        if (index < 0) return;
        this.waiting.splice(index, 1);
        reject(this.stopped());
      };
      this.waiting.push(grant);
      stopSignal?.addEventListener('abort', abandon);
    });
  }

  private release(): void {
    // The slot passes to the first waiter, so a new request cannot take it
    // first.
    const next = this.waiting.shift();
    if (next) next();
    else this.inFlight--;
  }
}

/**
 * Protocol phases in order, with a barrier between phases. A phase starts only
 * after the phase before it settled and succeeded, and not after the stop
 * signal aborts. A phase that starts too early throws and runs nothing.
 */
export class FanOutPhases {
  private state: 'ready' | 'running' | 'failed' = 'ready';

  constructor(
    private readonly fanOut: BoundedFanOut,
    private readonly stopped: () => Error,
    private readonly stopSignal?: AbortSignal
  ) {}

  /** Run one fan-out phase: all() with the stop signal of these phases. */
  all<T, R>(items: readonly T[], task: (item: T, index: number) => Promise<R>): Promise<R[]> {
    return this.run(() => this.fanOut.all(items, task, this.stopSignal));
  }

  /** Run one phase that is not a fan-out, for example one request. */
  async run<R>(phase: () => Promise<R>): Promise<R> {
    if (this.state === 'running') {
      throw new Error('A phase started before the phase before it settled');
    }
    if (this.state === 'failed') {
      throw new Error('A phase started after the phase before it failed');
    }
    if (this.stopSignal?.aborted) throw this.stopped();
    this.state = 'running';
    try {
      const result = await phase();
      this.state = 'ready';
      return result;
    } catch (error) {
      this.state = 'failed';
      throw error;
    }
  }
}
