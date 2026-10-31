/**
 * The Signal Protocol Relay refused an HTTP request.
 *
 * `status` is the HTTP status. `code`, `message`, and `retryable` come from
 * the Relay's error body. `code` is `UNKNOWN` when the body has none. The SDK
 * also throws this error with the Relay's status and code when it finds the
 * refusal before it sends the request.
 *
 * A custom `HostedRelayManagedDeviceLinkAdapter` throws this error when the
 * Relay refuses the link, with the Relay's `code` and `retryable`.
 * `linkHostedRelayDevice` rolls the link back only for this error, with
 * `retryable` false and the code `KEY_PROOF_INVALID` or `CONFLICT`. It keeps
 * the link state for every other error.
 */
export class HostedRelayHttpError extends Error {
  /** The Relay's error code, for example `KEY_PROOF_INVALID`. */
  public readonly code: string;
  /** More values of the refusal. A refused declared post keeps the Relay's `details` here. */
  public readonly data?: Readonly<Record<string, unknown>>;
  /** The HTTP status of the response. */
  public readonly status: number;
  /**
   * The Relay's own hint that the same operation can be sent again. On an
   * error that `send()` throws before its posting deadline, the SDK sets
   * `retryable` to true and keeps this hint in `relayRetryable`.
   */
  public readonly retryable: boolean;

  /** `retryable` is false when `options` does not give it. */
  public constructor(
    status: number,
    code: string,
    message: string,
    options?: {
      readonly data?: Readonly<Record<string, unknown>>;
      readonly retryable?: boolean;
    },
  ) {
    super(message);
    this.name = "HostedRelayHttpError";
    this.status = status;
    this.code = code;
    this.data = options?.data;
    this.retryable = options?.retryable ?? false;
  }
}
