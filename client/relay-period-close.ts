/**
 * Relay period close: the Relay's PERIOD_CLOSED refusal of one delivery post,
 * and the one repeat of the same request that follows it.
 *
 * The Relay refuses a new admission with PERIOD_CLOSED when its admission
 * period ended before the admission. The refusal comes after the duplicate
 * check and before the Relay stores anything, and the Relay reads the period
 * again for each request. So the refusal proves that the Relay did not
 * accept the post, and one repeat of the same request can be admitted in the
 * next period. The repeat keeps the message ID, the operation epoch, and the
 * bytes of the post. A second PERIOD_CLOSED reaches the caller, and the send
 * keeps the device pending.
 *
 * The sealed route gives each code outside its safe codes as DELIVERY_FAILED,
 * so its carrier marks a PERIOD_CLOSED error here.
 *
 * No package entry exports this module. The mark is internal to the SDK.
 *
 * @internal
 */

const periodClosed = new WeakSet<object>();

/** Mark an error as the Relay's PERIOD_CLOSED refusal. Returns the same error. */
export function markPeriodClosed<T>(error: T): T {
  if (error !== null && typeof error === 'object') periodClosed.add(error);
  return error;
}

/** True when the Relay refused the post with PERIOD_CLOSED. */
export function isPeriodClosed(error: unknown): boolean {
  if (error === null || typeof error !== 'object') return false;
  return periodClosed.has(error) || (error as { code?: unknown }).code === 'PERIOD_CLOSED';
}

/**
 * Make the repeat rule of one post. Each call of the returned function runs
 * `post`. After a PERIOD_CLOSED answer, it awaits `beforeRepeat` and runs the
 * same post one more time. The rule repeats once for the whole post, also
 * when the post makes more requests for other reasons, so a second
 * PERIOD_CLOSED reaches the caller. Each other answer reaches the caller.
 * When `beforeRepeat` rejects, no repeat starts and the PERIOD_CLOSED error
 * is thrown.
 */
export function onePeriodClosedRetry(): <T>(
  post: () => Promise<T>,
  beforeRepeat?: () => Promise<void>
) => Promise<T> {
  let spent = false;
  return async (post, beforeRepeat) => {
    try {
      return await post();
    } catch (error) {
      if (spent || !isPeriodClosed(error)) throw error;
      spent = true;
      try {
        await beforeRepeat?.();
      } catch {
        throw error;
      }
      return post();
    }
  };
}
