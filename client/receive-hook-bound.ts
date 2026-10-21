/**
 * The receive hook bound: the longest time that a receive pass waits for
 * one application hook.
 *
 * A pass awaits each hook that it calls, so a hook that never settles would
 * stop the queue. Each call therefore races a timer of
 * `protocol.receiveQueue.receiveHookTimeoutMs`. At the bound, the call logs
 * `RECEIVE_HOOK_TIMEOUT` once and rejects with ReceiveHookTimeout. The pass
 * then handles the timeout as it handles a thrown error of that call:
 *
 * - A timeout of `onMessageDecrypted`, or of a hook whose error the pass
 *   gives back to it such as `onDelivered`, counts as one hook attempt,
 *   with the normal backoff and the attempt cap.
 * - A timeout of a hook that `callHook` calls, or of `onDeliveryRecovered`,
 *   ends that call, and the pass continues.
 *
 * The internal profile key exchange is not an application hook, and the
 * bound does not apply to it.
 *
 * The bounded call keeps running, but no SDK step waits for it. So its late
 * result or error reaches no SDK step, and the pass writes nothing for it.
 * A relay work item wraps each bounded hook, so the item stops counting as
 * waiting in the app at the timeout.
 *
 * Signal equivalence. One Signal client runs each receive task and each
 * event dispatch under its 2-minute short-lived bound, and its application
 * handlers under its 30-minute long-running bound. The SDK
 * bounds each hook at the 2-minute receive bound by default, and the
 * application can change it. docs/DEVIATIONS.md records the deviation.
 */

import type { Logger } from '../logger';
import type { SignalProtocolClientHooks } from './event-hooks';

/** The default of `protocol.receiveQueue.receiveHookTimeoutMs`: 2 minutes. */
export const RECEIVE_HOOK_TIMEOUT_MS = 120_000;

/** The log behavior of a call that did not settle within the bound. */
export const RECEIVE_HOOK_TIMEOUT = 'RECEIVE_HOOK_TIMEOUT';

/**
 * Thrown in a receive pass when a hook did not settle within the receive
 * hook bound. The bound logged it.
 *
 * @internal
 */
export class ReceiveHookTimeout extends Error {
  constructor(
    /** The name of the hook. */
    readonly hook: string,
    /** The bound that the call passed. */
    readonly timeoutMs: number
  ) {
    super(`The ${hook} call did not settle within ${timeoutMs} ms`);
    this.name = 'ReceiveHookTimeout';
  }
}

/**
 * Run one call under the receive hook bound.
 *
 * @returns The result of the call, when it settles within the bound
 * @throws The error of the call, when it rejects within the bound
 * @throws ReceiveHookTimeout at the bound, after one log
 */
export function boundReceiveCall<T>(
  hook: string,
  timeoutMs: number,
  logger: Pick<Required<Logger>, 'warn'>,
  call: () => T | Promise<T>
): Promise<T> {
  let settled: Promise<T>;
  try {
    settled = Promise.resolve(call());
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise<T>((resolve, reject) => {
    let open = true;
    const timer = setTimeout(() => {
      if (!open) return;
      open = false;
      logger.warn('A receive hook did not settle within its bound', {
        category: 'E2EE',
        data: { hook, timeoutMs, behavior: RECEIVE_HOOK_TIMEOUT },
      });
      reject(new ReceiveHookTimeout(hook, timeoutMs));
    }, timeoutMs);
    // The bound alone does not keep a Node process alive.
    (timer as { unref?: () => void }).unref?.();
    // A settle after the timeout reaches no SDK step. Its rejection is
    // handled here, so it is not an unhandled rejection.
    settled.then(
      (value) => {
        if (!open) return;
        open = false;
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        if (!open) return;
        open = false;
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

/**
 * Hooks that run each call under the receive hook bound. A receive pass
 * wraps these hooks in its relay work.
 */
export function boundReceiveHooks(
  hooks: SignalProtocolClientHooks,
  timeoutMs: number,
  logger: Pick<Required<Logger>, 'warn'>
): SignalProtocolClientHooks {
  const bound: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  for (const [name, hook] of Object.entries(hooks)) {
    if (typeof hook !== 'function') continue;
    const call = hook as (...args: unknown[]) => unknown;
    bound[name] = (...args) =>
      boundReceiveCall(name, timeoutMs, logger, () => Reflect.apply(call, undefined, args));
  }
  return bound as SignalProtocolClientHooks;
}
