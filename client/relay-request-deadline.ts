/**
 * The deadline of one hosted Relay HTTP request.
 *
 * A device post holds a slot of the client's relay request bound, and its
 * send holds the send lock of the recipient, until the post settles. A fetch
 * has no deadline of its own in a browser, so a request that never answers,
 * as on a dropped connection, would hold both with no end. Each hosted Relay
 * request therefore aborts at this deadline, response body included. The
 * Relay drops a repeat of an operation that it accepted, so the caller can
 * send the same operation again.
 */

/** The time that one hosted Relay request, response body included, can take. */
export const RELAY_REQUEST_DEADLINE_MILLISECONDS = 30_000;

/**
 * Run one hosted Relay request with a signal that aborts at the deadline. The
 * request must pass the signal to fetch and read the response body before it
 * returns, so the deadline covers the whole exchange.
 *
 * A request that fails after the deadline rejects with "Signal Protocol Relay
 * request could not be completed", whose cause is a "Signal Protocol Relay
 * request timed out" error. The error is the same whether fetch or the body
 * read failed, and whatever error the platform gives for the abort: the
 * React Native fetch, for one, drops the abort reason.
 */
export async function withRelayRequestDeadline<T>(
  request: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const deadline = new AbortController();
  const timeout = new Error("Signal Protocol Relay request timed out");
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    deadline.abort(timeout);
  }, RELAY_REQUEST_DEADLINE_MILLISECONDS);
  try {
    return await request(deadline.signal);
  } catch (error) {
    if (!timedOut) throw error;
    throw new Error("Signal Protocol Relay request could not be completed", {
      cause: timeout,
    });
  } finally {
    clearTimeout(timer);
  }
}
