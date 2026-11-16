/**
 * The deadline of one HTTP request to the OpenE2EE Signal Protocol Relay.
 *
 * A device post holds a slot of the client's relay request bound, and its
 * send holds the send lock of the recipient, until the post settles. A fetch
 * has no deadline of its own in a browser, so a request that never answers,
 * as on a dropped connection, would hold both with no end. Each Relay request
 * therefore aborts at this deadline, response body included. The Relay drops a
 * repeat of an operation that it accepted, so the caller can send the same
 * operation again.
 */

/** The time that one Relay request, response body included, can take. */
export const SIGNAL_RELAY_REQUEST_DEADLINE_MILLISECONDS = 30_000;

/** The errors that `signalProtocolRelayRequestNotCompleted` made. */
const notCompletedRequests = new WeakSet<Error>();

/**
 * The error of a Relay request that got no answer: fetch failed, or the
 * deadline passed. The error is a plain `Error` with the message "Signal
 * Protocol Relay request could not be completed" and `cause`. A caller that
 * sends the same operation again finds the error with
 * `isSignalProtocolRelayRequestNotCompleted`, not by its message.
 */
export function signalProtocolRelayRequestNotCompleted(cause: unknown): Error {
  const error = new Error("Signal Protocol Relay request could not be completed", { cause });
  notCompletedRequests.add(error);
  return error;
}

/**
 * Whether `error` is the error of a Relay request that got no answer, as made by
 * `signalProtocolRelayRequestNotCompleted`. An error with the same message from
 * a different source is not.
 */
export function isSignalProtocolRelayRequestNotCompleted(error: unknown): boolean {
  return error instanceof Error && notCompletedRequests.has(error);
}

/**
 * Run one Relay request with a signal that aborts at the deadline. The request
 * must pass the signal to fetch and read the response body before it returns,
 * so the deadline covers the whole exchange.
 *
 * A request that fails after the deadline rejects with the error of
 * `signalProtocolRelayRequestNotCompleted`, whose cause is a "Signal Protocol
 * Relay request timed out" error. The error is the same whether fetch or the body
 * read failed, and whatever error the platform gives for the abort: the
 * React Native fetch, for one, drops the abort reason.
 */
export async function withSignalProtocolRelayRequestDeadline<T>(
  request: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const deadline = new AbortController();
  const timeout = new Error("Signal Protocol Relay request timed out");
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    deadline.abort(timeout);
  }, SIGNAL_RELAY_REQUEST_DEADLINE_MILLISECONDS);
  try {
    return await request(deadline.signal);
  } catch (error) {
    if (!timedOut) throw error;
    throw signalProtocolRelayRequestNotCompleted(timeout);
  } finally {
    clearTimeout(timer);
  }
}
