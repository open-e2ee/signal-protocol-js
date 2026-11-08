/** Failures of strict hosted resume, without application or key payloads. */
export type HostedSignalProtocolRelayResumePhase =
  'reading-local-state' | 'authenticating' | 'initializing' | 'complete';
export interface HostedSignalProtocolRelayResumeProgress {
  readonly phase: HostedSignalProtocolRelayResumePhase;
}
export type HostedSignalProtocolRelayResumeProgressCallback = (
  progress: HostedSignalProtocolRelayResumeProgress,
) => void;
export type HostedSignalProtocolRelayResumeErrorCode =
  | 'RETAINED_IDENTITY_UNAVAILABLE'
  | 'RETAINED_IDENTITY_CHANGED'
  | 'RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE'
  | 'RETAINED_SESSION_UNAVAILABLE'
  | 'RETAINED_STATE_UNREADABLE'
  | 'RESUME_CLEANUP_UNRESOLVED';

let retainCleanup: (
  error: HostedSignalProtocolRelayResumeError,
  cleanup: () => Promise<void>,
) => void;
/** A strict-resume refusal. An unresolved cleanup remains owned by this error. */
export class HostedSignalProtocolRelayResumeError extends Error {
  #cleanup?: () => Promise<void>;
  #settling?: Promise<void>;
  static #retainedCleanup = (retainCleanup = (error, cleanup) => {
    error.#cleanup = cleanup;
  });
  constructor(
    readonly code: HostedSignalProtocolRelayResumeErrorCode,
    readonly phase: HostedSignalProtocolRelayResumePhase,
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
  error: HostedSignalProtocolRelayResumeError,
  cleanup: () => Promise<void>,
): void {
  retainCleanup(error, cleanup);
}

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `HostedSignalProtocolRelayResumeError`. SDK 15.0.0 removes this name. */
export const HostedRelayResumeError = HostedSignalProtocolRelayResumeError;
/** @deprecated Use `HostedSignalProtocolRelayResumeError`. SDK 15.0.0 removes this name. */
export type HostedRelayResumeError = HostedSignalProtocolRelayResumeError;
/** @deprecated Use `HostedSignalProtocolRelayResumeErrorCode`. SDK 15.0.0 removes this name. */
export type HostedRelayResumeErrorCode = HostedSignalProtocolRelayResumeErrorCode;
/** @deprecated Use `HostedSignalProtocolRelayResumePhase`. SDK 15.0.0 removes this name. */
export type HostedRelayResumePhase = HostedSignalProtocolRelayResumePhase;
/** @deprecated Use `HostedSignalProtocolRelayResumeProgress`. SDK 15.0.0 removes this name. */
export type HostedRelayResumeProgress = HostedSignalProtocolRelayResumeProgress;
/** @deprecated Use `HostedSignalProtocolRelayResumeProgressCallback`. SDK 15.0.0 removes this name. */
export type HostedRelayResumeProgressCallback = HostedSignalProtocolRelayResumeProgressCallback;
