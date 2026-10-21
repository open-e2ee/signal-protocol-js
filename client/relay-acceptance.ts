import type { RetryFailureClass, RetryTerminalClass } from '../local/store/reliability';

/** What the relay reports about one post that it accepted. */
export interface RelayPostAcceptance {
  messageId: string;
  serverTimestamp: number;
  /** True when the relay had already accepted this exact post. */
  duplicate?: boolean;
  /** The time at which the relay drops the copy that a device has not acknowledged. */
  expiresAt?: number;
  /** True when the relay compared the declared device set of this post. */
  deviceSetChecked?: boolean;
  /** True when the sender account has other devices that need a sync copy. */
  needsSync?: boolean;
}

/**
 * The acceptance of a whole send from the acceptance of each of its posts.
 *
 * The send is a duplicate only when the relay had already accepted every
 * post, and the earliest expiry bounds the whole send. A field is present only
 * when every post reported it, so a send with no post has neither field.
 * The device-set marks are not part of the aggregate. The device-set
 * reconciliation reads them from each post.
 */
export function aggregateRelayAcceptance(
  posts: readonly Pick<RelayPostAcceptance, 'duplicate' | 'expiresAt'>[]
): { duplicate?: boolean; expiresAt?: number } {
  if (posts.length === 0) return {};
  const duplicates = posts.map((post) => post.duplicate);
  const expiries = posts.map((post) => post.expiresAt);
  return {
    ...(duplicates.every((duplicate) => duplicate !== undefined) && {
      duplicate: duplicates.every(Boolean),
    }),
    ...(expiries.every((expiry) => expiry !== undefined) && {
      expiresAt: Math.min(...(expiries as number[])),
    }),
  };
}

/**
 * The Relay's refusal of one delivery operation. OPERATION_EXPIRED: the
 * operation epoch is outside the admission window or the replay horizon.
 * RETRY_CONFLICT: the Relay holds another operation under the same message ID.
 */
export type RelayOperationRefusal = 'OPERATION_EXPIRED' | 'RETRY_CONFLICT';

/** The operation refusal that a relay error carries as its code, if any. */
export function relayOperationRefusal(error: unknown): RelayOperationRefusal | undefined {
  if (error === null || typeof error !== 'object') return undefined;
  const { code } = error as { code?: unknown };
  return code === 'OPERATION_EXPIRED' || code === 'RETRY_CONFLICT' ? code : undefined;
}

/** The class of a retry request post that the Relay or the transport refused. */
export type RetryRequestPostFailure =
  | { terminal: RetryTerminalClass }
  | { retry: RetryFailureClass };

/**
 * The codes that end a retry request when the Relay does not mark them
 * `retryable`. The hosted transport gets a new device token once on
 * TOKEN_INVALID and posts again, so a TOKEN_INVALID that reaches this
 * classifier is a refusal of the new token too. The SDK cannot get a token
 * that the Relay accepts, so the authority of the device is revoked.
 */
const TERMINAL_CODES: ReadonlyMap<string, RetryTerminalClass> = new Map([
  ['STALE_DEVICE', 'missing-sender'],
  ['NOT_FOUND', 'deletion'],
  ['AUTHORITY_DENIED', 'revoked-authority'],
  ['AUTHORITY_OVERRIDE', 'revoked-authority'],
  ['TOKEN_INVALID', 'revoked-authority'],
]);

const RATE_CODES: ReadonlySet<string> = new Set(['QUOTA_EXCEEDED', 'MAILBOX_FULL']);

/**
 * Classify the error of a retry request post.
 *
 * The Relay's `retryable` hint comes first: the Relay sets it when the same
 * post can succeed later, for example while a Relay binding is missing. A
 * retryable error is a rate refusal for QUOTA_EXCEEDED, MAILBOX_FULL or 429,
 * and a transport outage for every other code, AUTHORITY_DENIED included.
 *
 * Without the hint, the error code comes next, then the HTTP status. A
 * conclusive class ends the request: STALE_DEVICE or 410 is a missing
 * sender, NOT_FOUND or 404 is a deletion, and AUTHORITY_DENIED,
 * AUTHORITY_OVERRIDE, TOKEN_INVALID, 401 or 403 is a revoked authority.
 * QUOTA_EXCEEDED, MAILBOX_FULL and 429 are a rate refusal. Every other
 * error, a network error and a lost answer included, is a transport outage.
 * The caller handles OPERATION_EXPIRED and RETRY_CONFLICT first.
 */
export function classifyRetryRequestPostFailure(error: unknown): RetryRequestPostFailure {
  if (error === null || typeof error !== 'object') return { retry: 'transport-outage' };
  const { code, status, retryable } = error as {
    code?: unknown;
    status?: unknown;
    retryable?: unknown;
  };
  const rate = (typeof code === 'string' && RATE_CODES.has(code)) || status === 429;
  if (retryable === true) return { retry: rate ? 'rate-refusal' : 'transport-outage' };
  if (typeof code === 'string') {
    const terminal = TERMINAL_CODES.get(code);
    if (terminal) return { terminal };
  }
  if (rate) return { retry: 'rate-refusal' };
  if (status === 410) return { terminal: 'missing-sender' };
  if (status === 404) return { terminal: 'deletion' };
  if (status === 401 || status === 403) return { terminal: 'revoked-authority' };
  return { retry: 'transport-outage' };
}
