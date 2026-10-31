import type { RetryFailureClass, RetryTerminalClass } from '../local/store/reliability';
import { relayAnswerVersion } from './relay-protocol';

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
 * The Relay's refusal of one delivery operation.
 *
 * OPERATION_EXPIRED has four sources: an operation epoch more than 5 minutes
 * ahead of the Relay clock, an epoch older than the 24-hour replay horizon, an
 * accepted operation before the end of the retained period, and an epoch
 * older than the admission window with no stored operation.
 *
 * RETRY_CONFLICT has three sources: the Relay holds the same operation with
 * other bytes, the same operation under another accepted class, or another
 * operation under the same message ID. A direct post that never changed its
 * bytes counts it as an earlier acceptance, under protocol version 1 and
 * version 2.
 *
 * DELIVERY_ALREADY_ACCEPTED is a protocol version 2 code: the Relay already
 * holds an accepted post under the message ID, so it refused this post
 * before it stored anything. A post and a retry request both read it as
 * RETRY_CONFLICT. Under version 1 the Relay sends RETRY_CONFLICT in its
 * place, so a version 1 answer with this code is an unknown code.
 */
export type RelayOperationRefusal =
  | 'OPERATION_EXPIRED'
  | 'RETRY_CONFLICT'
  | 'DELIVERY_ALREADY_ACCEPTED';

const conflictAcceptances = new WeakSet<RelayPostAcceptance>();

/**
 * The acceptance of a post that got RETRY_CONFLICT, or DELIVERY_ALREADY_ACCEPTED
 * under protocol version 2: the Relay already holds a post under its message
 * ID. Neither answer carries a Relay receipt, so the acceptance carries only
 * the client message ID of the post and the time of the answer on the SDK
 * clock.
 */
export function conflictAcceptance(
  clientMessageId: string,
  serverTimestamp: number
): RelayPostAcceptance {
  const acceptance: RelayPostAcceptance = { messageId: clientMessageId, serverTimestamp };
  conflictAcceptances.add(acceptance);
  return acceptance;
}

/** True for an acceptance that `conflictAcceptance` made. */
export function isConflictAcceptance(acceptance: RelayPostAcceptance): boolean {
  return conflictAcceptances.has(acceptance);
}

/**
 * The acceptance that gives the message ID and time of a send result: the
 * first one with a Relay receipt, else the first one.
 */
export function sendResultAcceptance(
  acceptances: readonly RelayPostAcceptance[]
): RelayPostAcceptance | undefined {
  return acceptances.find((acceptance) => !isConflictAcceptance(acceptance)) ?? acceptances[0];
}

/**
 * The operation refusal that a relay error carries as its code, if any.
 * DELIVERY_ALREADY_ACCEPTED is a refusal only when a hosted carrier marked
 * the error as the answer to a request of protocol version 2 or later. An
 * unmarked error and a version 1 answer carry it as an unknown code.
 */
export function relayOperationRefusal(error: unknown): RelayOperationRefusal | undefined {
  if (error === null || typeof error !== 'object') return undefined;
  const { code } = error as { code?: unknown };
  if (code === 'OPERATION_EXPIRED' || code === 'RETRY_CONFLICT') return code;
  if (code === 'DELIVERY_ALREADY_ACCEPTED' && (relayAnswerVersion(error) ?? 1) >= 2) {
    return code;
  }
  return undefined;
}

/**
 * True when a relay error says that the Relay already holds a post under the
 * message ID of the post: RETRY_CONFLICT, or DELIVERY_ALREADY_ACCEPTED under
 * protocol version 2. A post reads both answers in the same way.
 */
export function relayHoldsMessageId(error: unknown): boolean {
  const refusal = relayOperationRefusal(error);
  return refusal === 'RETRY_CONFLICT' || refusal === 'DELIVERY_ALREADY_ACCEPTED';
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
 * The caller handles OPERATION_EXPIRED, RETRY_CONFLICT and the version 2
 * DELIVERY_ALREADY_ACCEPTED first. A version 1 DELIVERY_ALREADY_ACCEPTED is
 * an unknown code, so it is a transport outage.
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
