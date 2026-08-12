/**
 * Shared rejection contract for every fuzz target.
 *
 * A decoder handed malformed input must reject it with its own controlled
 * `Error`. Anything else escaping the seam — a `TypeError` or `RangeError`
 * surfacing from a built-in, a non-Error throw — is a finding, so it is
 * rethrown for the fuzzing engine to report.
 */
export function allowOnlyControlledError(error, alsoAllowed = []) {
  if (
    error instanceof Error &&
    (error.constructor === Error ||
      alsoAllowed.some((allowedClass) => error.constructor === allowedClass))
  ) {
    return;
  }
  throw error;
}
