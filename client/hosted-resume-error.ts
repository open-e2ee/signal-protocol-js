/** Failures of strict hosted resume, without application or key payloads. */
export type HostedRelayResumePhase =
  'reading-local-state' | 'authenticating' | 'initializing' | 'complete';
export interface HostedRelayResumeProgress {
  readonly phase: HostedRelayResumePhase;
}
export type HostedRelayResumeProgressCallback = (
  progress: HostedRelayResumeProgress,
) => void;
export type HostedRelayResumeErrorCode =
  | 'RETAINED_IDENTITY_UNAVAILABLE'
  | 'RETAINED_IDENTITY_CHANGED'
  | 'RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE'
  | 'RETAINED_SESSION_UNAVAILABLE'
  | 'RETAINED_STATE_UNREADABLE'
  | 'RESUME_CLEANUP_UNRESOLVED';

let retainCleanup: (
  error: HostedRelayResumeError,
  cleanup: () => Promise<void>,
) => void;
/** A strict-resume refusal. An unresolved cleanup remains owned by this error. */
export class HostedRelayResumeError extends Error {
  #cleanup?: () => Promise<void>;
  #settling?: Promise<void>;
  static #retainedCleanup = (retainCleanup = (error, cleanup) => {
    error.#cleanup = cleanup;
  });
  constructor(
    readonly code: HostedRelayResumeErrorCode,
    readonly phase: HostedRelayResumePhase,
    options?: ErrorOptions,
  ) {
    super('The existing hosted device could not be resumed.', options);
    this.name = 'HostedRelayResumeError';
  }
  /** True while this error still owns a client whose stop has not completed. */
  get cleanupPending(): boolean {
    return this.#cleanup !== undefined;
  }
  /** Retry only the held client's stop. Never retries resume or closes storage. */
  async retryCleanup(): Promise<void> {
    if (this.#settling) return this.#settling;
    const cleanup = this.#cleanup;
    if (!cleanup) return;
    this.#settling = (async () => {
      await cleanup();
      this.#cleanup = undefined;
    })();
    try {
      await this.#settling;
    } finally {
      this.#settling = undefined;
    }
  }
}
/** @internal Transfer the actual failed-stop handle into the public error. */
export function retainHostedResumeCleanup(
  error: HostedRelayResumeError,
  cleanup: () => Promise<void>,
): void {
  retainCleanup(error, cleanup);
}
