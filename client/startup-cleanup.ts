/** Retain the actual startup handle when its cleanup has not settled. */
/** @internal This error owns cleanup only; it cannot restart initialization. */
export class ClientStartupCleanupError extends Error {
  constructor(
    readonly failure: unknown,
    readonly cleanupFailure: unknown,
    readonly retryCleanup: () => Promise<void>,
  ) {
    super('Client startup cleanup has not settled.', { cause: failure });
  }
}
