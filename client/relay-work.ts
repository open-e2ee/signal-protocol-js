/**
 * Relay work: the deliveries, retry requests, and receipt sends that the
 * relay starts and that stop() must settle.
 *
 * The relay calls its handlers without waiting for them. Each call runs as
 * one RelayWork item. At any time an item runs SDK work, or waits in an app
 * hook. stop() stops every item and waits only for the items that run SDK
 * work. It does not wait for time in app hooks, because a hook can itself
 * await stop(), and without async context the SDK cannot tell that call from
 * a call outside the hook.
 *
 * A stopped item may not enter an app hook, and an item that leaves an app
 * hook after stop() starts throws RelayWorkStopped. So no SDK step after the
 * hook runs, and the relay delivers the envelope again after the next start.
 *
 * An item can hold a lock while it waits in an app hook. So an item that
 * waits for a lock stops waiting when stop() stops it, and throws
 * RelayWorkStopped.
 */

import type AsyncLock from 'async-lock';

import type { SignalProtocolClientHooks } from './event-hooks';

/**
 * Thrown in relay work that stop() stopped. The tracker absorbs it, so it
 * never reaches the relay or the app.
 *
 * @internal
 */
export class RelayWorkStopped extends Error {
  constructor() {
    super('The client stopped during relay work');
    this.name = 'RelayWorkStopped';
  }
}

/** Rethrow a RelayWorkStopped that a catch-all caught. */
export function rethrowRelayWorkStopped(error: unknown): void {
  if (error instanceof RelayWorkStopped) throw error;
}

/**
 * The state of one relay work item: running SDK work, waiting in an app
 * hook, or stopped.
 *
 * @internal
 */
export class RelayWork {
  private appCalls = 0;
  private readonly stopper = new AbortController();

  constructor(private readonly changed: () => void) {}

  /** Aborts when stop() stops this item. */
  get stopSignal(): AbortSignal {
    return this.stopper.signal;
  }

  /** True while the item waits in an app hook and runs no SDK work. */
  get inApp(): boolean {
    return this.appCalls > 0;
  }

  /** Throw RelayWorkStopped if stop() stopped this item. */
  proceed(): void {
    if (this.stopper.signal.aborted) throw new RelayWorkStopped();
  }

  /** Stop the item. Its next SDK step after an app hook throws. */
  stop(): void {
    this.stopper.abort();
  }

  /**
   * Call app code. The item counts as waiting in the app until the call
   * settles. After a stop, the exit throws RelayWorkStopped in place of the
   * result or the app error, so no SDK step after the call runs.
   */
  async callApp<T>(call: () => T | Promise<T>): Promise<T> {
    this.proceed();
    this.appCalls++;
    this.changed();
    try {
      return await call();
    } finally {
      this.appCalls--;
      this.changed();
      this.proceed();
    }
  }

  /** Hooks that call the app through this item. */
  wrapHooks(hooks: SignalProtocolClientHooks): SignalProtocolClientHooks {
    const wrapped: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
    for (const [name, hook] of Object.entries(hooks)) {
      if (typeof hook !== 'function') continue;
      const call = hook as (...args: unknown[]) => unknown;
      wrapped[name] = (...args) => this.callApp(() => Reflect.apply(call, undefined, args));
    }
    return wrapped as SignalProtocolClientHooks;
  }
}

/**
 * Run a task under a lock. When the stop signal aborts while the task waits
 * for the lock, the wait ends with RelayWorkStopped, and the task never runs.
 * A task that holds the lock runs on. A task that finds the lock free takes
 * it, also after the abort. Without a signal, this is lock.acquire().
 */
export function acquireUntilStopped<T>(
  lock: AsyncLock,
  key: string,
  task: () => Promise<T>,
  stopSignal?: AbortSignal
): Promise<T> {
  if (!stopSignal) return lock.acquire(key, task);
  return new Promise<T>((resolve, reject) => {
    let waiting = true;
    const abandon = () => {
      if (!waiting) return;
      waiting = false;
      reject(new RelayWorkStopped());
    };
    lock
      .acquire(key, async () => {
        stopSignal.removeEventListener('abort', abandon);
        // An abandoned wait releases the lock at once.
        if (!waiting) return undefined;
        waiting = false;
        return task();
      })
      .then((result) => resolve(result as T), reject);
    // A free lock ran the task at once, so the wait is over.
    if (!waiting) return;
    if (stopSignal.aborted) abandon();
    else stopSignal.addEventListener('abort', abandon);
  });
}

/**
 * The relay work items in progress.
 *
 * @internal
 */
export class RelayWorkTracker {
  private readonly items = new Set<RelayWork>();
  private readonly waiters = new Set<() => void>();
  private stopping = 0;

  /**
   * Run a task as a relay work item. While stop() settles, the item starts
   * stopped. A RelayWorkStopped from the task resolves the returned promise.
   * Other errors reject it.
   */
  async run(task: (work: RelayWork) => Promise<void>): Promise<void> {
    const work = new RelayWork(() => this.notify());
    if (this.stopping > 0) work.stop();
    this.items.add(work);
    try {
      await task(work);
    } catch (error) {
      if (!(error instanceof RelayWorkStopped)) throw error;
    } finally {
      this.items.delete(work);
      this.notify();
    }
  }

  /**
   * Stop every item and wait until each item settles or waits in an app hook.
   * Items that start during the wait start stopped, and the wait includes them.
   * Never rejects.
   */
  async settle(): Promise<void> {
    this.stopping++;
    try {
      for (const work of this.items) work.stop();
      while (![...this.items].every((work) => work.inApp)) {
        await new Promise<void>((resolve) => this.waiters.add(resolve));
      }
    } finally {
      this.stopping--;
    }
  }

  private notify(): void {
    const waiters = [...this.waiters];
    this.waiters.clear();
    for (const resolve of waiters) resolve();
  }
}
