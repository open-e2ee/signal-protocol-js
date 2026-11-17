import { bytesToUrlSafeBase64, generateRandomBytes, generateUuidV4 } from '../internal/crypto';
import type { SignalProtocolLocalStore } from '../types';
import { resolveHostedSignalProtocolRelayConnection, type HostedSignalProtocolRelayConnection } from './hosted-connection';
import { getExistingDeviceAuthentication } from './hosted-device-authentication';
import { HostedSignalProtocolRelayHttpError } from './hosted-http-error';
import {
  assertRetainedHostedSignalProtocolRelaySession,
  hostedSignalProtocolRelayAccountScopeDigest,
  resumeHostedSignalProtocolRelayTransport,
} from './hosted-transport';
import { postJson, record } from './signal-relay-http';
import { signalRelayProtocolOffer } from './signal-relay-protocol';

/** The exact deletion state that the Signal Protocol Relay confirms. */
export interface HostedSignalProtocolRelayAccountDeletionReceipt {
  readonly schemaVersion: 1;
  readonly operationId: string;
  readonly logicalDeletionConfirmed: boolean;
  readonly capacityRelease: 'pending' | 'released' | 'not_applicable';
  readonly purgeState: 'purging' | 'complete';
}

/** Options for the retained account store and Relay URL. */
export interface HostedSignalProtocolRelayAccountDeletionOptions {
  /**
   * The same open encrypted store that the hosted client uses.
   * Keep this store after deletion to retain the status capability and receipt.
   * Stop the client before deletion. The caller owns the store and its closure.
   */
  readonly storage: SignalProtocolLocalStore;
  /**
   * The public environment-scoped Signal Protocol Relay connection URL of the hosted client.
   * Another URL of the same environment, publishable key, and Relay scope finds the same intent.
   */
  readonly relayUrl: string;
}

export type HostedSignalProtocolRelayAccountDeletionErrorCode =
  | 'DELETION_UNSUPPORTED'
  | 'DELETION_STATE_INVALID'
  | 'DELETION_INTENT_UNAVAILABLE'
  | 'DELETION_ALREADY_REQUESTED'
  | 'DELETION_PREFLIGHT_PENDING';

/** A deletion contract failure. It contains no status capability or device token. */
export class HostedSignalProtocolRelayAccountDeletionError extends Error {
  public constructor(public readonly code: HostedSignalProtocolRelayAccountDeletionErrorCode) {
    super({
      DELETION_UNSUPPORTED: 'Signal Protocol Relay does not support deletion receipts',
      DELETION_STATE_INVALID: 'Account deletion state is invalid',
      DELETION_INTENT_UNAVAILABLE: 'The store has no retained account deletion intent',
      DELETION_ALREADY_REQUESTED: 'The store retains an account deletion intent. Read its deletion status',
      DELETION_PREFLIGHT_PENDING:
        'The store retains an account deletion that the SDK has not submitted. Continue it with deleteHostedSignalProtocolRelayAccount',
    }[code]);
    this.name = 'HostedSignalProtocolRelayAccountDeletionError';
  }
}

interface DeletionIntent {
  readonly schemaVersion: 2;
  readonly phase: 'preflight' | 'submitted';
  readonly operationId: string;
  readonly deletionStatusToken: string;
  readonly receipt: HostedSignalProtocolRelayAccountDeletionReceipt | null;
}

type SubmittedDeletionIntent = DeletionIntent & { readonly phase: 'submitted' };

const INTENT_PREFIX = 'signalRelay.accountDeletion.v1:';
const RECEIPT_KEYS = ['schemaVersion', 'operationId', 'logicalDeletionConfirmed', 'capacityRelease', 'purgeState'];
const INTENT_KEYS = ['schemaVersion', 'phase', 'operationId', 'deletionStatusToken', 'receipt'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CAPABILITY = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;

function invalid(): never {
  throw new HostedSignalProtocolRelayAccountDeletionError('DELETION_STATE_INVALID');
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function receipt(value: unknown, operationId: string): HostedSignalProtocolRelayAccountDeletionReceipt {
  if (record(value) && value.schemaVersion !== undefined && value.schemaVersion !== 1) {
    throw new HostedSignalProtocolRelayAccountDeletionError('DELETION_UNSUPPORTED');
  }
  if (!record(value) || !exactKeys(value, RECEIPT_KEYS) || value.schemaVersion !== 1 ||
      value.operationId !== operationId || typeof value.logicalDeletionConfirmed !== 'boolean' ||
      !['pending', 'released', 'not_applicable'].includes(value.capacityRelease as string) ||
      !['purging', 'complete'].includes(value.purgeState as string) ||
      (value.capacityRelease === 'released' && !value.logicalDeletionConfirmed) ||
      (value.purgeState === 'complete' && !value.logicalDeletionConfirmed)) invalid();
  return {
    schemaVersion: 1,
    operationId,
    logicalDeletionConfirmed: value.logicalDeletionConfirmed as boolean,
    capacityRelease: value.capacityRelease as HostedSignalProtocolRelayAccountDeletionReceipt['capacityRelease'],
    purgeState: value.purgeState as HostedSignalProtocolRelayAccountDeletionReceipt['purgeState'],
  };
}

// The intent has the account scope of the hosted session, so each Relay URL of that account finds it.
async function intentKey(connection: HostedSignalProtocolRelayConnection): Promise<string> {
  return `${INTENT_PREFIX}${await hostedSignalProtocolRelayAccountScopeDigest(connection)}`;
}

function parseIntent(value: string): DeletionIntent {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { invalid(); }
  if (!record(parsed) || parsed.schemaVersion !== 2 || !exactKeys(parsed, INTENT_KEYS) ||
      !['preflight', 'submitted'].includes(parsed.phase as string) ||
      typeof parsed.operationId !== 'string' || !UUID.test(parsed.operationId) ||
      typeof parsed.deletionStatusToken !== 'string' || !CAPABILITY.test(parsed.deletionStatusToken)) invalid();
  return {
    schemaVersion: 2,
    phase: parsed.phase as DeletionIntent['phase'],
    operationId: parsed.operationId,
    deletionStatusToken: parsed.deletionStatusToken,
    receipt: parsed.receipt === null ? null : receipt(parsed.receipt, parsed.operationId),
  };
}

async function readIntent(storage: SignalProtocolLocalStore, key: string): Promise<DeletionIntent | undefined> {
  const value = await storage.getMetadata(key);
  return value === null ? undefined : parseIntent(value);
}

/**
 * @internal The deletion phase of the store for one hosted account.
 * `preflight` proves that the SDK sent no deletion request. `submitted` means that the Relay may hold one.
 * An invalid intent throws `DELETION_STATE_INVALID`.
 */
export type HostedSignalProtocolRelayAccountDeletionPhase = 'none' | 'preflight' | 'submitted';

/** @internal Reads the deletion phase of the store. It writes nothing and sends nothing. */
export async function readHostedSignalProtocolRelayAccountDeletionPhase(
  storage: SignalProtocolLocalStore,
  connection: HostedSignalProtocolRelayConnection,
): Promise<HostedSignalProtocolRelayAccountDeletionPhase> {
  const intent = await readIntent(storage, await intentKey(connection));
  if (intent === undefined) return 'none';
  return intent.phase === 'preflight' && intent.receipt === null ? 'preflight' : 'submitted';
}

async function retainReceipt(
  storage: SignalProtocolLocalStore,
  key: string,
  intent: DeletionIntent,
  next: HostedSignalProtocolRelayAccountDeletionReceipt,
): Promise<HostedSignalProtocolRelayAccountDeletionReceipt> {
  for (;;) {
    const stored = await storage.getMetadata(key);
    if (stored === null) invalid();
    const current = parseIntent(stored);
    if (current.operationId !== intent.operationId || current.deletionStatusToken !== intent.deletionStatusToken) invalid();
    const previous = current.receipt;
    if (previous !== null && (
      (previous.logicalDeletionConfirmed && !next.logicalDeletionConfirmed) ||
      (previous.capacityRelease !== 'pending' && previous.capacityRelease !== next.capacityRelease) ||
      (previous.purgeState === 'complete' && next.purgeState !== 'complete')
    )) invalid();
    if (await storage.compareAndSetMetadata(key, stored, JSON.stringify({ ...current, phase: 'submitted', receipt: next }))) return next;
  }
}

async function retainSubmission(
  storage: SignalProtocolLocalStore,
  key: string,
  intent: DeletionIntent,
): Promise<SubmittedDeletionIntent> {
  for (;;) {
    const stored = await storage.getMetadata(key);
    if (stored === null) invalid();
    const current = parseIntent(stored);
    if (current.operationId !== intent.operationId || current.deletionStatusToken !== intent.deletionStatusToken) invalid();
    if (current.phase === 'submitted') return { ...current, phase: 'submitted' };
    const submitted: SubmittedDeletionIntent = { ...current, phase: 'submitted' };
    if (await storage.compareAndSetMetadata(key, stored, JSON.stringify(submitted))) return submitted;
  }
}

function requestBody(connection: HostedSignalProtocolRelayConnection, intent: DeletionIntent) {
  return {
    publishableKey: connection.publishableKey,
    operationId: intent.operationId,
    receiptVersion: 1,
    deletionStatusToken: intent.deletionStatusToken,
  };
}

/**
 * Maps an absent deletion route to `DELETION_UNSUPPORTED`. The status route has proved
 * deletion support before this request, so a `404` is a refusal of the Relay and keeps its error.
 */
function rethrowUnsupported(error: unknown): never {
  if (error instanceof HostedSignalProtocolRelayHttpError &&
      (error.status === 405 || error.status === 501 || error.code === 'RECEIPT_UNSUPPORTED')) {
    throw new HostedSignalProtocolRelayAccountDeletionError('DELETION_UNSUPPORTED');
  }
  throw error;
}

const RECEIPT_VERSION_HEADER = 'x-signal-relay-deletion-receipt-version';
// The statuses of an absent route. A Relay without the deletion routes answers with them.
const ABSENT_ROUTE_STATUSES = [404, 405, 501];

/**
 * Requires the receipt marker on each status answer that can show an absent route:
 * a success, or a refusal with an absent-route status that is not retryable.
 * The protocol handling runs first: Relay ingress refuses a protocol version
 * before the route, so that refusal has no marker and keeps its own meaning.
 * Each other refusal, for example a `5xx` from the edge, also keeps its own error.
 */
function requireReceiptVersion(response: Response, refusal?: HostedSignalProtocolRelayHttpError): void {
  if (refusal !== undefined && (!ABSENT_ROUTE_STATUSES.includes(refusal.status) || refusal.retryable)) return;
  if (response.headers.get(RECEIPT_VERSION_HEADER) !== '1') {
    throw new HostedSignalProtocolRelayAccountDeletionError('DELETION_UNSUPPORTED');
  }
}

async function readStatus(
  options: HostedSignalProtocolRelayAccountDeletionOptions,
  connection: HostedSignalProtocolRelayConnection,
  key: string,
  intent: DeletionIntent,
): Promise<HostedSignalProtocolRelayAccountDeletionReceipt> {
  const answer = await postJson(
    connection, signalRelayProtocolOffer(), '/identity/deletion/status', requestBody(connection, intent), undefined,
    requireReceiptVersion,
  );
  return retainReceipt(options.storage, key, intent, receipt(answer, intent.operationId));
}

/**
 * Request deletion with the retained device authority. This call never registers an account.
 * A store without the retained device authentication or session of the hosted account
 * gets a `HostedSignalProtocolRelayResumeError`, and the call writes nothing and sends nothing.
 * Otherwise the SDK saves one operation and a secret status capability before the first status request.
 * Each attempt reads versioned status before submission, including after a lost response or process restart.
 *
 * The saved operation binds the store to the hosted account, also when the first attempt fails
 * before it submits the request. Before submission, `createHostedSignalProtocolClient` runs the
 * strict resume of `resumeHostedSignalProtocolClient` for that account, and it reports the
 * `bootstrap` progress of an ordinary resume. A recovery, a re-registration, and a custom
 * protocol manager refuse with `DELETION_PREFLIGHT_PENDING`. After submission,
 * `createHostedSignalProtocolClient` and `resumeHostedSignalProtocolClient` refuse with
 * `DELETION_ALREADY_REQUESTED`.
 * A later call continues the same operation. Only `storage.clearAllKeys()` discards the binding,
 * and then the SDK keeps no record of a deletion that the Relay may have received.
 *
 * Acknowledgment and `capacityRelease: 'pending'` do not confirm a free slot.
 * Only `capacityRelease: 'released'` confirms release. No timer infers release.
 * The call preserves identities, protocol state, and failed deletion intents.
 *
 * @throws HostedSignalProtocolRelayResumeError `RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE` or
 * `RETAINED_SESSION_UNAVAILABLE` when the store does not retain the hosted account.
 * @throws HostedSignalProtocolRelayAccountDeletionError `DELETION_UNSUPPORTED` when the Relay
 * has no versioned deletion receipt route, and `DELETION_STATE_INVALID` when the stored intent
 * or a Relay receipt is invalid.
 * @throws HostedSignalProtocolRelayHttpError `404` with code `NOT_FOUND` when the Relay refuses
 * the deletion request, or has no status for a submitted operation. The intent stays, and a later
 * call reads its status again. Each other Relay refusal also keeps its own error.
 */
export async function deleteHostedSignalProtocolRelayAccount(
  options: HostedSignalProtocolRelayAccountDeletionOptions,
): Promise<HostedSignalProtocolRelayAccountDeletionReceipt> {
  const connection = await resolveHostedSignalProtocolRelayConnection(options.relayUrl);
  const key = await intentKey(connection);
  let intent = await readIntent(options.storage, key);
  if (intent?.receipt?.logicalDeletionConfirmed) return { ...intent.receipt };
  if (intent === undefined) {
    // A new intent binds the store to its hosted account, so only a store that retains that account
    // creates one. These checks read local state only. An existing intent stays readable without them.
    await getExistingDeviceAuthentication(options.storage, connection.publishableKey, true);
    await assertRetainedHostedSignalProtocolRelaySession(options.storage, connection);
    const candidate: DeletionIntent = {
      schemaVersion: 2,
      phase: 'preflight',
      operationId: await generateUuidV4(),
      deletionStatusToken: bytesToUrlSafeBase64(await generateRandomBytes(32)),
      receipt: null,
    };
    if (await options.storage.compareAndSetMetadata(key, null, JSON.stringify(candidate))) {
      intent = candidate;
    } else {
      intent = await readIntent(options.storage, key);
      if (intent === undefined) invalid();
    }
  }
  try {
    return await readStatus(options, connection, key, intent);
  } catch (error) {
    // Only the versioned status route can authorize exact request submission.
    if (!(error instanceof HostedSignalProtocolRelayHttpError) || error.status !== 404 || error.code !== 'NOT_FOUND') throw error;
    if (intent.receipt !== null) throw error;
  }
  const deviceAuthentication = await getExistingDeviceAuthentication(options.storage, connection.publishableKey, true);
  const resumed = await resumeHostedSignalProtocolRelayTransport({
    connection, deviceAuthentication, storage: options.storage, requireExisting: true,
  });
  if (resumed === undefined) invalid();
  const submitted = await retainSubmission(options.storage, key, intent);
  if (submitted.receipt !== null) return { ...submitted.receipt };
  const answer = await resumed.transport.requestAccountDeletion(submitted).catch(rethrowUnsupported);
  if (!record(answer) || answer.acknowledged !== true || answer.state !== 'purging') invalid();
  return retainReceipt(options.storage, key, submitted, receipt(answer.receipt, submitted.operationId));
}

/**
 * Read deletion status with the retained secret capability, without a device token.
 * The store and `relayUrl` must match the deletion request.
 * This call reads status once. Failed and unknown reads preserve the intent.
 * Keep the store until the Relay confirms the required release and purge state.
 *
 * @throws HostedSignalProtocolRelayAccountDeletionError `DELETION_INTENT_UNAVAILABLE` when the
 * store has no deletion intent, `DELETION_UNSUPPORTED` when the Relay has no versioned deletion
 * receipt route, and `DELETION_STATE_INVALID` when the stored intent or a Relay receipt is invalid.
 * @throws HostedSignalProtocolRelayHttpError `404` with code `NOT_FOUND` when the Relay has no
 * status for the operation, for example before the deletion request reaches it.
 * Each other Relay refusal also keeps its own error.
 */
export async function readHostedSignalProtocolRelayAccountDeletion(
  options: HostedSignalProtocolRelayAccountDeletionOptions,
): Promise<HostedSignalProtocolRelayAccountDeletionReceipt> {
  const connection = await resolveHostedSignalProtocolRelayConnection(options.relayUrl);
  const key = await intentKey(connection);
  const intent = await readIntent(options.storage, key);
  if (intent === undefined) throw new HostedSignalProtocolRelayAccountDeletionError('DELETION_INTENT_UNAVAILABLE');
  if (intent.receipt?.purgeState === 'complete' && intent.receipt.capacityRelease !== 'pending') return { ...intent.receipt };
  return readStatus(options, connection, key, intent);
}
