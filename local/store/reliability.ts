import type { Envelope } from '../../remote/relay/types';
import type { SignalProtocolLocalStore } from '../../types';
import type { ContentHint } from '../../types/messages';
import { createKeyedLocks, withKeyedLock } from '../../utils/keyed-lock';
import { originLockScope, withOriginLock } from '../../utils/origin-lock';

const OUTBOX_PREFIX = 'reliability:exact-ciphertext-outbox:v2';
const INCOMING_PREFIX = 'reliability:processed-envelopes:v2';
const RETRY_REQUESTED_PREFIX = 'reliability:retry-requested:v2';
const RETRY_RESEND_PREFIX = 'reliability:retry-resend:v1';
const RETRY_FAMILY_PREFIX = 'reliability:retry-family:v1';
const SENT_TIMESTAMP_PREFIX = 'reliability:sent-timestamps:v1';
const DELIVERY_STATUS_PREFIX = 'reliability:delivery-status:v1';
const RECEIVED_TIMESTAMP_PREFIX = 'reliability:received-timestamps:v1';
const DAY_MS = 24 * 60 * 60 * 1_000;

export const RELIABILITY_RECORD_TTL_MS = 30 * DAY_MS;

/**
 * The posting window of an outgoing intent. No request of the intent starts
 * at or after `outgoingMessageDeadlineAt`.
 */
export const OUTGOING_POSTING_WINDOW_MS = DAY_MS;

/**
 * The lifetime of the retry-request and retry-family records of the
 * requester, and of a fulfilled processed-envelope record. Two bounds set
 * it. A sender refuses a retry request for a message older than
 * `RELIABILITY_RECORD_TTL_MS`, so its last resend post comes at most that
 * long after the failure. The Relay keeps a post for at most
 * `RELIABILITY_RECORD_TTL_MS`, so a resend can arrive up to twice that
 * time after the failure.
 */
export const RETRY_REQUESTER_RECORD_TTL_MS = 2 * RELIABILITY_RECORD_TTL_MS;

/**
 * The time from the first failure of a retry request to its end: 14 days,
 * the default retention of resendable content of a sender,
 * `RESENDABLE_CONTENT_RETENTION_MS`. A request whose content did not come
 * at this time ends as `expired-content`.
 */
export const RETRY_REQUEST_DEADLINE_MS = 14 * DAY_MS;

/**
 * The posting window of a retry request: 24 hours from the first failure,
 * `receivedAt`. No post of the request starts at or after
 * `retryRequestPostingDeadlineAt`.
 */
export const RETRY_REQUEST_POSTING_WINDOW_MS = DAY_MS;

export interface StoredOutgoingDeviceMessage {
  recipientUserId: string;
  recipientDeviceId: number;
  timestamp: number;
  clientMessageId?: string;
  ciphertext: string;
  messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key';
  recipientRegistrationId?: number;
  sealedSenderMessage?: string;
  sealedSenderAccessKey?: string;
  sealedSenderAuthorization?: 'access_key' | 'group_send_token';
  sealedSenderDeliveryMode?: 'preferred' | 'required';
  /**
   * The own sender key that a distribution pre-message gives. When the Relay
   * accepts the pre-message, the send records a handoff row for this key and
   * `recipientRegistrationId`. It holds no key material.
   */
  senderKeyHandoff?: { senderKeyId: string; generation: number };
}

export interface StoredGroupSharedMessage {
  groupId: string;
  sentMessageBase64: string;
  recipientUserIds: string[];
  deliveryMode: 'preferred' | 'required';
}

export interface StoredOutgoingMessageIntent {
  kind: 'direct' | 'group';
  clientMessageId: string;
  recipientId: string;
  plaintextDigest: string;
  clientTimestamp: number;
  createdAt: number;
  transportMode: 'identified' | 'sealed_sender_preferred' | 'sealed_sender_required';
  sealedSenderAuth?: { type: 'accessKey'; unidentifiedAccessKey: string };
  contentHint?: ContentHint;
  /**
   * The attachment of a binary send. `message` is the exact serialized
   * attachment message that the intent encrypts, and `fileDigest` is the
   * base64 SHA-256 digest of the source file. A repeat of the send with the
   * same file sends `message` again and uploads nothing. The record keeps it
   * for its life, also after completion.
   */
  binaryAttachment?: { fileDigest: string; message: string };
  preMessages?: StoredOutgoingDeviceMessage[];
  deviceMessages: StoredOutgoingDeviceMessage[];
  syncMessages: StoredOutgoingDeviceMessage[];
  groupMemberUserIds?: string[];
  groupRecipientDeviceCount?: number;
  groupCiphertext?: string;
  groupSenderKeyDistributionId?: string;
  groupSharedMessage?: StoredGroupSharedMessage;
  /**
   * A direct send posted before it read the recipient's device list, and has
   * not yet applied the list to this intent.
   */
  reconcilePending?: true;
  /**
   * The restarts of each phase of a declared send. The write that commits a
   * repair also adds one to the count of its phase.
   */
  deviceSetRestarts?: { recipient?: number; sync?: number };
  /** The terminal record of a phase that ended without reconciliation. */
  deviceSetUnresolved?: StoredDeviceSetUnresolved;
  /**
   * The listed devices of each phase of a declared send that had no prekey
   * bundle at the last repair of the phase. They have no message in the
   * intent. A replay starts a session with each of them before its first
   * post, so a device that uploaded a bundle after the repair gets the
   * message. A terminal end keeps them, and no later replay posts to them.
   */
  deviceSetBundleMissing?: {
    recipient?: OutgoingGroupDevice[];
    sync?: OutgoingGroupDevice[];
  };
  /**
   * On a declared intent, the recipient phase completed and the sync phase
   * did not. The intent keeps its sync messages, and a replay before
   * `deadlineAt` posts only them. At or after `deadlineAt`, a replay posts
   * nothing and returns the stored result with `syncPending`. With no sync
   * messages, the read of the own device list failed, and a replay reads it
   * again. When that read finds no other own device, the replay completes the
   * sync phase with no post and returns the result without `syncPending`.
   *
   * On an undeclared intent, the posting deadline stopped the sync posts. A
   * replay returns the stored result with `syncPending` and posts nothing.
   */
  syncPending?: true;
  /**
   * The posting deadline: the earlier of `createdAt` and `clientTimestamp`,
   * plus `OUTGOING_POSTING_WINDOW_MS`. The first write stores it. An intent
   * that an earlier SDK stored gets it at its next mutation write, from the
   * same terms. No request of the intent starts at or after it.
   */
  deadlineAt?: number;
  /**
   * The end of an open intent at its posting deadline. Its absence means
   * that the intent is open. `result` takes precedence over it.
   */
  outcome?: 'failed' | 'acceptance-unknown';
  /**
   * The SDK send driver ended or completed this intent and has not yet
   * reported the end through `onSendOutcome`. The end write or the completion
   * write sets it. The driver clears it before it calls the hook, so a crash
   * before the clear reports the end at the next start. An application send
   * never sets it: its end is reported in memory.
   */
  outcomeReportPending?: true;
  /** The time at which the driver cleared `outcomeReportPending`. */
  outcomeReportedAt?: number;
  /**
   * The SDK made this send for itself, as a sender key distribution. Its
   * end never reaches `onSendOutcome`, from an application call or from the
   * driver, so no end write sets `outcomeReportPending` on it.
   */
  internal?: true;
  /**
   * The progress of each destination device, keyed by
   * `outgoingDestinationProgressKey`. A send writes the entry of a device
   * before each request and after each answer, and the end write merges the
   * class of each recipient device. The completion keeps it.
   */
  destinationProgress?: Record<string, StoredDestinationProgress>;
  /**
   * The intent wrote the progress of each destination before each of its
   * requests, from its first write. Without it, an earlier SDK can have
   * posted a destination with no progress written, so a new entry starts
   * uncertain.
   */
  progressFromStart?: true;
  /**
   * The manual resends of an ended intent, in the order of their start. An
   * intent with no resend has no field, and `outgoingManualResends` reads it
   * as an empty list.
   */
  manualResends?: StoredManualResend[];
  result?: {
    clientMessageId: string;
    messageId: string;
    timestamp: number;
    recipientDeviceCount: number;
    duplicate?: boolean;
    expiresAt?: number;
    refusedDestinationCount?: number;
    groupId?: string;
  };
}

/**
 * One manual resend of an ended intent. It is a new operation: its posts
 * carry `manualMessageId` and its own operation epoch, and its posting
 * deadline is its own. The content of each message keeps the client
 * timestamp of the intent. The intent keeps its own epoch, `deadlineAt` and
 * `outcome`.
 */
export interface StoredManualResend {
  /** The client message ID of each post of the resend: `<clientMessageId>:manual:N`, N from 1. */
  manualMessageId: string;
  /** The time of the first write of the resend. One clock read gives it and the epoch. */
  createdAt: number;
  /** The operation epoch of each post of the resend. */
  operationEpochMilliseconds: number;
  /** The posting deadline of the resend: `createdAt` plus `OUTGOING_POSTING_WINDOW_MS`. */
  deadlineAt: number;
  /** The encrypted message of each destination device, which each post of the resend sends again. */
  messages: StoredManualResendMessage[];
  /** The progress of each destination of the resend, keyed by `outgoingDestinationProgressKey`. */
  destinationProgress?: Record<string, StoredDestinationProgress>;
  /** The Relay result, when the Relay accepted each destination of the resend. */
  result?: StoredOutgoingMessageIntent['result'];
  /** The end of the resend at its posting deadline. `result` takes precedence over it. */
  outcome?: NonNullable<StoredOutgoingMessageIntent['outcome']>;
  /** The time of the end write of the resend, which also gives its report. */
  outcomeReportedAt?: number;
}

/** The encrypted message of one destination device of a manual resend. */
export interface StoredManualResendMessage {
  transportMode: StoredOutgoingMessageIntent['transportMode'];
  /**
   * The sealed authorization of the post. A group endorsement is stored by
   * its group, and the endorsement of the device's account resolves again
   * at each post.
   */
  sealedSenderAuth?:
    | { type: 'accessKey'; unidentifiedAccessKey: string }
    | { type: 'groupSendToken'; groupId: string };
  contentHint?: ContentHint;
  message: StoredOutgoingDeviceMessage;
}

/** The progress of one destination device of an outgoing intent. */
export interface StoredDestinationProgress {
  phase: 'recipient' | 'sync';
  userId: string;
  deviceId: number;
  /** The client message ID that the posts to this device carry. */
  postMessageId: string;
  state: 'pending' | 'posted' | 'accepted' | 'refused' | 'unknown';
  /** The number of requests that started for this device. */
  requests: number;
  /**
   * A request for this device can have reached the Relay with no answer
   * that proves its outcome. Once set, it stays set.
   */
  uncertain?: true;
  /**
   * A repair replaced the message of this device after a stale
   * registration: a stale-device repair, or a device-set repair that
   * removed this device. The Relay can hold the replaced message under the
   * message ID, sealed to the old session, so a `RETRY_CONFLICT` answer to
   * the repost does not prove acceptance. A repair that only adds a missing
   * device sets `repairedFor` and not this mark: the Relay stores nothing
   * under the message ID for a device-set refusal, so a `RETRY_CONFLICT`
   * answer for an added device names a copy that another writer posted
   * while the device was registered. No released SDK version wrote
   * `repaired` or `repairedFor` (13.3.0 is the last release), so no
   * migration reads an earlier meaning.
   */
  repaired?: true;
  /**
   * The recovery that the last repair of this device ran, and the client
   * message ID of the message that it stored. Each repair sets it, with or
   * without `repaired`. An entry that has `repaired` without this field
   * counts each refusal as a refusal of its repair.
   */
  repairedFor?: {
    recovery: 'stale-device' | 'device-set';
    postMessageId: string;
  };
  /**
   * The Relay code of the last answer when that answer is a refusal, or the
   * kind of a refusal with no Relay code: `device-set`, `sealed-sender-auth`
   * or `device-rejection`. A later request or a later answer of another
   * class clears it.
   */
  refusalCode?: string;
  /** The recovery for the refusal ran, and the Relay refused the repost too. */
  repairSpent?: true;
  generation?: number;
  messageId?: string;
  enqueuedAt?: number;
  expiresAt?: number;
  duplicate?: true;
}

/** The terminal record of a declared send phase that ended without reconciliation. */
export interface StoredDeviceSetUnresolved {
  phase: 'recipient' | 'sync';
  reason: 'exhausted' | 'expired';
  restarts: number;
  lastRefusal?: {
    code: 'DEVICE_SET_MISMATCH' | 'STALE_DEVICE' | 'BUNDLE_NOT_FOUND';
    accounts: {
      userId: string;
      missingDeviceIds: number[];
      extraDeviceIds: number[];
      staleDeviceIds: number[];
    }[];
  };
}

type ReliabilityMetadataStore = Pick<
  SignalProtocolLocalStore,
  'getMetadata' | 'setMetadata' | 'deleteMetadata'
> &
  Partial<Pick<SignalProtocolLocalStore, 'listMetadataKeys'>>;
type LedgerKind =
  | 'outbox'
  | 'incoming'
  | 'retry-requested'
  | 'retry-family'
  | 'retry-resend'
  | 'sent-timestamp'
  | 'delivery-status'
  | 'received-timestamp';

const mutationTails = new WeakMap<object, Promise<void>>();
const outgoingIntentLocks = createKeyedLocks();
const outgoingIntentEndReports = new WeakMap<object, Map<string, OutgoingIntentEndReport>>();
const incomingEnvelopeLocks = createKeyedLocks();

const LEDGER_PREFIXES: Record<LedgerKind, string> = {
  outbox: OUTBOX_PREFIX,
  incoming: INCOMING_PREFIX,
  'retry-requested': RETRY_REQUESTED_PREFIX,
  'retry-family': RETRY_FAMILY_PREFIX,
  'retry-resend': RETRY_RESEND_PREFIX,
  'sent-timestamp': SENT_TIMESTAMP_PREFIX,
  'delivery-status': DELIVERY_STATUS_PREFIX,
  'received-timestamp': RECEIVED_TIMESTAMP_PREFIX,
};

const LEDGER_TTL_MS: Record<LedgerKind, number> = {
  outbox: RELIABILITY_RECORD_TTL_MS,
  incoming: RELIABILITY_RECORD_TTL_MS,
  'retry-requested': RETRY_REQUESTER_RECORD_TTL_MS,
  'retry-family': RETRY_REQUESTER_RECORD_TTL_MS,
  'retry-resend': RELIABILITY_RECORD_TTL_MS,
  'sent-timestamp': RELIABILITY_RECORD_TTL_MS,
  'delivery-status': RELIABILITY_RECORD_TTL_MS,
  // Two bounds: the last manual resend of a sender posts at most
  // RELIABILITY_RECORD_TTL_MS after its intent, and the Relay keeps a post
  // for at most RELIABILITY_RECORD_TTL_MS.
  'received-timestamp': RETRY_REQUESTER_RECORD_TTL_MS,
};

function prefix(kind: LedgerKind): string {
  return LEDGER_PREFIXES[kind];
}

function recordKey(kind: LedgerKind, id: string): string {
  return `${prefix(kind)}:record:${encodeURIComponent(id)}`;
}

function bucketKey(kind: LedgerKind, day: number): string {
  return `${prefix(kind)}:bucket:${day}`;
}

function manifestKey(kind: LedgerKind): string {
  return `${prefix(kind)}:manifest`;
}

function dayFor(timestamp: number): number {
  return Math.floor(timestamp / DAY_MS);
}

function parseJson<T>(value: string | null, fallback: T): T {
  if (value === null) return fallback;
  return JSON.parse(value) as T;
}

function cloneReliabilityValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

async function serializeMutation<T>(
  store: ReliabilityMetadataStore,
  operation: () => Promise<T>
): Promise<T> {
  const key = store as object;
  const previous = mutationTails.get(key) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  mutationTails.set(
    key,
    current.then(
      () => undefined,
      () => undefined
    )
  );
  return current;
}

/**
 * The end of one send call, as the end write or the completion write of its
 * intent records it. The send call that holds the intent lock gives it.
 */
export interface OutgoingIntentEndReport {
  /** The SDK send driver made the call. Its end write then sets `outcomeReportPending`. */
  readonly driven: boolean;
  /**
   * The SDK made the send for itself. A new intent of the call stores
   * `internal`, and its end is never reported.
   */
  readonly internal?: true;
  /**
   * The intent as the call ended or completed it. Only a write that ends an
   * open intent sets it: a replay of an ended or completed intent does not.
   */
  ended?: StoredOutgoingMessageIntent;
}

/** The end report of the send call that holds the lock of this intent. */
function outgoingIntentEndReport(
  store: ReliabilityMetadataStore,
  clientMessageId: string
): OutgoingIntentEndReport | undefined {
  return outgoingIntentEndReports.get(store as object)?.get(clientMessageId);
}

/**
 * Run `operation` under the lock of one outgoing intent. When
 * `navigator.locks.request` exists and the store sets `storeIdentity`, the
 * lock is the Web Lock `open-e2ee:outbox:<store identity>:<clientMessageId>`,
 * so the tabs, workers and threads of one origin that share the store share
 * it. Otherwise it is an in-process lock keyed by the store object. The lock
 * is not reentrant. With `report`, an end write or a completion write of the
 * intent during `operation` records the end in it.
 */
export async function withOutgoingMessageIntentLock<T>(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  operation: () => Promise<T>,
  report?: OutgoingIntentEndReport
): Promise<T> {
  const reported = report
    ? async () => {
        let reports = outgoingIntentEndReports.get(store as object);
        if (!reports) {
          reports = new Map();
          outgoingIntentEndReports.set(store as object, reports);
        }
        reports.set(clientMessageId, report);
        try {
          return await operation();
        } finally {
          reports.delete(clientMessageId);
        }
      }
    : operation;
  const scope = originLockScope(store);
  if (scope !== null) {
    return withOriginLock(`open-e2ee:outbox:${scope}:${clientMessageId}`, reported);
  }
  return withKeyedLock(outgoingIntentLocks, store, clientMessageId, reported);
}

export async function withProcessedEnvelopeLock<T>(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  operation: () => Promise<T>
): Promise<T> {
  return withKeyedLock(incomingEnvelopeLocks, store, envelopeId, operation);
}

async function pruneExpiredBuckets(
  store: ReliabilityMetadataStore,
  kind: LedgerKind,
  now: number
): Promise<number[]> {
  const days = parseJson<number[]>(await store.getMetadata(manifestKey(kind)), []);
  const firstRetainedDay = dayFor(now - LEDGER_TTL_MS[kind]);
  const manifest = new Set(days);
  for (const day of days) {
    if (day >= firstRetainedDay) continue;
    const ids = parseJson<string[]>(await store.getMetadata(bucketKey(kind, day)), []);
    for (const id of ids) {
      if (kind === 'outbox' && (await keepOutgoingIntent(store, id, now, manifest))) continue;
      await store.deleteMetadata(recordKey(kind, id));
    }
    await store.deleteMetadata(bucketKey(kind, day));
  }
  return [...manifest].filter((day) => day >= firstRetainedDay).sort((a, b) => a - b);
}

/**
 * Keep an intent of an expired outbox bucket that a manual resend retains,
 * and index it under the day of `outgoingIntentRetainedFrom`. The bucket and
 * the manifest are written before the expired bucket is deleted, so a stop
 * leaves the intent in a bucket.
 *
 * @returns True when the intent is kept.
 */
async function keepOutgoingIntent(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  now: number,
  manifest: Set<number>
): Promise<boolean> {
  const record = parseJson<StoredOutgoingMessageIntent | null>(
    await store.getMetadata(recordKey('outbox', clientMessageId)),
    null
  );
  if (!record) return false;
  const retainedFrom = outgoingIntentRetainedFrom(record);
  if (retainedFrom < now - RELIABILITY_RECORD_TTL_MS) return false;
  const day = dayFor(retainedFrom);
  const dayKey = bucketKey('outbox', day);
  const ids = parseJson<string[]>(await store.getMetadata(dayKey), []);
  if (!ids.includes(clientMessageId)) {
    ids.push(clientMessageId);
    await store.setMetadata(dayKey, JSON.stringify(ids));
  }
  if (!manifest.has(day)) {
    manifest.add(day);
    await store.setMetadata(
      manifestKey('outbox'),
      JSON.stringify([...manifest].sort((a, b) => a - b))
    );
  }
  return true;
}

async function indexRecord(
  store: ReliabilityMetadataStore,
  kind: LedgerKind,
  id: string,
  timestamp: number,
  retainedDays: number[]
): Promise<void> {
  const day = dayFor(timestamp);
  const dayKey = bucketKey(kind, day);
  const ids = parseJson<string[]>(await store.getMetadata(dayKey), []);
  if (!ids.includes(id)) {
    ids.push(id);
    await store.setMetadata(dayKey, JSON.stringify(ids));
  }
  if (!retainedDays.includes(day)) {
    retainedDays.push(day);
    retainedDays.sort((a, b) => a - b);
  }
  await store.setMetadata(manifestKey(kind), JSON.stringify(retainedDays));
}

/** Remove one record ID from the bucket of its day, and the empty bucket from the manifest. */
async function unindexRecord(
  store: ReliabilityMetadataStore,
  kind: LedgerKind,
  id: string,
  timestamp: number
): Promise<void> {
  const day = dayFor(timestamp);
  const dayKey = bucketKey(kind, day);
  const ids = parseJson<string[]>(await store.getMetadata(dayKey), []).filter(
    (candidate) => candidate !== id
  );
  if (ids.length > 0) {
    await store.setMetadata(dayKey, JSON.stringify(ids));
    return;
  }
  await store.deleteMetadata(dayKey);
  const days = parseJson<number[]>(await store.getMetadata(manifestKey(kind)), []);
  await store.setMetadata(
    manifestKey(kind),
    JSON.stringify(days.filter((retainedDay) => retainedDay !== day))
  );
}

function sameIntent(a: StoredOutgoingMessageIntent, b: StoredOutgoingMessageIntent): boolean {
  const sameLogicalIntent =
    a.clientMessageId === b.clientMessageId &&
    a.kind === b.kind &&
    a.recipientId === b.recipientId &&
    a.plaintextDigest === b.plaintextDigest &&
    a.clientTimestamp === b.clientTimestamp &&
    a.transportMode === b.transportMode &&
    a.contentHint === b.contentHint;
  if (!sameLogicalIntent || a.result) return sameLogicalIntent;
  return (
    a.reconcilePending === b.reconcilePending &&
    JSON.stringify(a.sealedSenderAuth) === JSON.stringify(b.sealedSenderAuth) &&
    JSON.stringify(a.preMessages) === JSON.stringify(b.preMessages) &&
    JSON.stringify(a.deviceMessages) === JSON.stringify(b.deviceMessages) &&
    JSON.stringify(a.syncMessages) === JSON.stringify(b.syncMessages) &&
    JSON.stringify(a.groupMemberUserIds) === JSON.stringify(b.groupMemberUserIds) &&
    a.groupRecipientDeviceCount === b.groupRecipientDeviceCount &&
    a.groupCiphertext === b.groupCiphertext &&
    a.groupSenderKeyDistributionId === b.groupSenderKeyDistributionId &&
    JSON.stringify(a.groupSharedMessage) === JSON.stringify(b.groupSharedMessage)
  );
}

/** One device of a group intent: an account and one of its devices. */
export interface OutgoingGroupDevice {
  userId: string;
  deviceId: number;
}

/** A change of the device set of a group intent. */
export interface OutgoingGroupDeviceSetChange {
  /** The devices whose pre-messages, device messages, and sync messages leave the intent. */
  removed: readonly OutgoingGroupDevice[];
  preMessages: readonly StoredOutgoingDeviceMessage[];
  deviceMessages: readonly StoredOutgoingDeviceMessage[];
  syncMessages: readonly StoredOutgoingDeviceMessage[];
  /**
   * The sealed shared body that replaces the stored body, or null when the
   * send no longer has a shared body. Absent when the body does not change.
   */
  groupSharedMessage?: StoredGroupSharedMessage | null;
}

/**
 * Apply a change of the device set to a group intent in one write. Each
 * removed device first loses all of its messages. Then each new message is
 * appended to its list. A new message for a device that still has a message
 * in the same list must be equal to it, and is not appended again. The same
 * write replaces or removes the shared body when the change names one.
 *
 * A device whose pre-message or device message the change appends after it
 * removed that device gets `repaired` and `repairedFor` on its progress
 * entry. The write creates the entry when none exists. A device that the
 * change appends without a removal gets no mark.
 */
export async function reconcileOutgoingGroupDeviceSet(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  change: OutgoingGroupDeviceSetChange
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'group' || existing.result) {
      throw new Error('Cannot change the devices of a missing or completed group outbox intent');
    }

    const removed = new Set(change.removed.map(outgoingDeviceKey));
    const kept = (messages: readonly StoredOutgoingDeviceMessage[]) =>
      messages.filter((message) => !removed.has(outgoingMessageDeviceKey(message)));
    const preMessages = appendOutgoingDeviceMessages(
      kept(existing.preMessages ?? []),
      change.preMessages
    );
    existing.deviceMessages = appendOutgoingDeviceMessages(
      kept(existing.deviceMessages),
      change.deviceMessages
    );
    existing.syncMessages = appendOutgoingDeviceMessages(
      kept(existing.syncMessages),
      change.syncMessages
    );
    if (preMessages.length > 0) existing.preMessages = preMessages;
    else delete existing.preMessages;
    applyGroupSharedMessage(existing, change.groupSharedMessage);
    for (const message of [...change.preMessages, ...change.deviceMessages]) {
      if (removed.has(outgoingMessageDeviceKey(message))) {
        markOutgoingDestinationRepaired(existing, 'recipient', message, 'stale-device', true);
      }
    }

    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Replace the shared body of a group intent, or remove it with null. An
 * absent body leaves the stored body.
 */
function applyGroupSharedMessage(
  intent: StoredOutgoingMessageIntent,
  groupSharedMessage: StoredGroupSharedMessage | null | undefined
): void {
  if (groupSharedMessage === null) delete intent.groupSharedMessage;
  else if (groupSharedMessage) {
    intent.groupSharedMessage = cloneReliabilityValue(groupSharedMessage);
  }
}

/** A repair of the device set of one phase of a declared send. */
export interface OutgoingDeviceSetRepair {
  phase: 'recipient' | 'sync';
  /** The restart count after this repair. It is one more than the stored count. */
  restarts: number;
  /** The devices whose pre-messages, device messages, and sync messages leave the intent. */
  removed: readonly OutgoingGroupDevice[];
  /**
   * The listed devices of the phase that had no prekey bundle at this
   * repair. They replace the stored bundle-missing devices of the phase.
   */
  bundleMissing?: readonly OutgoingGroupDevice[];
  preMessages?: readonly StoredOutgoingDeviceMessage[];
  deviceMessages?: readonly StoredOutgoingDeviceMessage[];
  syncMessages?: readonly StoredOutgoingDeviceMessage[];
  /**
   * The sealed shared body that replaces the refused body of a group send,
   * or null when no member of the send remains in a shared body.
   */
  groupSharedMessage?: StoredGroupSharedMessage | null;
}

/**
 * Commit the repair of a declared send phase and its restart count in one
 * write. Each removed device first loses all of its messages. Then each new
 * message is appended to its list, and the progress entry of its device
 * gets `repairedFor`. The entry of a device that the repair also removed
 * gets `repaired`, because the repair replaced its message. The entry of an
 * added device does not. A completed intent takes a repair only of its
 * pending sync phase, and a terminal intent takes none.
 *
 * @returns The stored intent, with the progress entry of each appended device
 */
export async function repairOutgoingDeviceSet(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  repair: OutgoingDeviceSetRepair
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || (existing.result && !(repair.phase === 'sync' && existing.syncPending))) {
      throw new Error('Cannot repair the device set of a missing or completed outbox intent');
    }
    if (existing.deviceSetUnresolved) {
      throw new Error('Cannot repair the device set of a terminal outbox intent');
    }
    const restarts = existing.deviceSetRestarts?.[repair.phase] ?? 0;
    if (repair.restarts !== restarts + 1) {
      throw new Error('Cannot repair the device set of an outbox intent from a different restart');
    }

    const removed = new Set(repair.removed.map(outgoingDeviceKey));
    const kept = (messages: readonly StoredOutgoingDeviceMessage[]) =>
      messages.filter((message) => !removed.has(outgoingMessageDeviceKey(message)));
    const preMessages = appendOutgoingDeviceMessages(
      kept(existing.preMessages ?? []),
      repair.preMessages ?? []
    );
    existing.deviceMessages = appendOutgoingDeviceMessages(
      kept(existing.deviceMessages),
      repair.deviceMessages ?? []
    );
    existing.syncMessages = appendOutgoingDeviceMessages(
      kept(existing.syncMessages),
      repair.syncMessages ?? [],
      'Cannot replace a persisted sync transmission'
    );
    if (preMessages.length > 0) existing.preMessages = preMessages;
    else delete existing.preMessages;
    const replaced = (message: StoredOutgoingDeviceMessage) =>
      removed.has(outgoingMessageDeviceKey(message));
    for (const message of [...(repair.preMessages ?? []), ...(repair.deviceMessages ?? [])]) {
      markOutgoingDestinationRepaired(existing, 'recipient', message, 'device-set', replaced(message));
    }
    for (const message of repair.syncMessages ?? []) {
      markOutgoingDestinationRepaired(existing, 'sync', message, 'device-set', replaced(message));
    }
    applyGroupSharedMessage(existing, repair.groupSharedMessage);
    existing.deviceSetRestarts = { ...existing.deviceSetRestarts, [repair.phase]: repair.restarts };
    const bundleMissing = (repair.bundleMissing ?? []).map((device) => ({
      userId: device.userId,
      deviceId: device.deviceId,
    }));
    const otherPhase = repair.phase === 'recipient' ? 'sync' : 'recipient';
    const otherMissing = existing.deviceSetBundleMissing?.[otherPhase];
    if (bundleMissing.length === 0 && !otherMissing) delete existing.deviceSetBundleMissing;
    else {
      existing.deviceSetBundleMissing = {
        ...(otherMissing && { [otherPhase]: otherMissing }),
        ...(bundleMissing.length > 0 && { [repair.phase]: bundleMissing }),
      };
    }

    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Record that a phase of a declared send ended without reconciliation. The
 * restart counts stay. A recipient-phase end stores the send outcome. A
 * later `send()` with the same `clientMessageId` then throws the stored-end
 * class and posts nothing. A sync-phase end keeps the result, and a later
 * `send()` posts the sync phase again. `resendMessage` posts a new
 * operation.
 *
 * `end` is the class of the recipient phase at the end: its outcome and the
 * progress of each recipient destination, which replaces the stored entry
 * under its key. Only a recipient-phase end of an open intent writes it.
 */
export async function markOutgoingDeviceSetUnresolved(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  unresolved: StoredDeviceSetUnresolved,
  end?: {
    outcome: NonNullable<StoredOutgoingMessageIntent['outcome']>;
    destinationProgress: Record<string, StoredDestinationProgress>;
  }
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || (existing.result && !(unresolved.phase === 'sync' && existing.syncPending))) {
      throw new Error('Cannot end the device set of a missing or completed outbox intent');
    }
    existing.deviceSetUnresolved = cloneReliabilityValue(unresolved);
    // A sync-phase end keeps the result of the recipient phase, so it
    // writes no outcome beside it.
    const ends =
      unresolved.phase === 'recipient' &&
      end !== undefined &&
      !existing.result &&
      existing.outcome === undefined;
    const report = ends ? outgoingIntentEndReport(store, clientMessageId) : undefined;
    if (ends) {
      if (report?.driven && !existing.internal) existing.outcomeReportPending = true;
      existing.outcome = end.outcome;
      existing.destinationProgress = {
        ...existing.destinationProgress,
        ...cloneReliabilityValue(end.destinationProgress),
      };
    }
    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    if (report) report.ended = cloneReliabilityValue(existing);
    return cloneReliabilityValue(existing);
  });
}

/**
 * Complete the pending sync phase of a completed intent: remove its sync
 * messages, its restart counts, and its terminal record.
 */
export async function completeOutgoingSyncPhase(
  store: ReliabilityMetadataStore,
  clientMessageId: string
): Promise<void> {
  await serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing?.result) throw new Error('Cannot complete the sync phase of an open intent');
    delete existing.syncPending;
    delete existing.deviceSetRestarts;
    delete existing.deviceSetUnresolved;
    delete existing.deviceSetBundleMissing;
    existing.syncMessages = [];
    await store.setMetadata(key, JSON.stringify(existing));
  });
}

/**
 * The result of a completed intent as a send returns it. A pending sync
 * phase gives `syncPending`.
 */
export function outgoingMessageIntentResult(
  intent: StoredOutgoingMessageIntent
): (NonNullable<StoredOutgoingMessageIntent['result']> & { syncPending?: true }) | undefined {
  if (!intent.result) return undefined;
  return {
    ...cloneReliabilityValue(intent.result),
    ...(intent.syncPending && { syncPending: true as const }),
  };
}

function outgoingDeviceKey({ userId, deviceId }: OutgoingGroupDevice): string {
  return `${userId}\u0000${String(deviceId)}`;
}

/**
 * The posting deadline of an intent: the stored `deadlineAt`, else the
 * earlier of `createdAt` and `clientTimestamp`, plus
 * `OUTGOING_POSTING_WINDOW_MS`. An intent that an earlier SDK stored has no
 * `deadlineAt`, and it gets the same value from its stored times.
 */
export function outgoingMessageDeadlineAt(
  intent: Pick<StoredOutgoingMessageIntent, 'createdAt' | 'clientTimestamp' | 'deadlineAt'>
): number {
  return (
    intent.deadlineAt ??
    Math.min(intent.createdAt, intent.clientTimestamp) + OUTGOING_POSTING_WINDOW_MS
  );
}

/** Store the posting deadline on an open intent that has none. */
function stampOutgoingDeadline(existing: StoredOutgoingMessageIntent): void {
  if (existing.result || existing.deadlineAt !== undefined) return;
  existing.deadlineAt = outgoingMessageDeadlineAt(existing);
}

/** The `destinationProgress` key of one device of one post. */
export function outgoingDestinationProgressKey(
  postMessageId: string,
  device: OutgoingGroupDevice
): string {
  return `${postMessageId}\u0000${outgoingDeviceKey(device)}`;
}

/**
 * The stored progress entry under this key, or a new `pending` entry with no
 * request. A new entry of an intent without `progressFromStart` starts
 * uncertain, because an earlier SDK can have posted the device.
 */
function outgoingDestinationProgressEntry(
  existing: StoredOutgoingMessageIntent,
  key: string,
  destination: Pick<StoredDestinationProgress, 'phase' | 'userId' | 'deviceId' | 'postMessageId'>
): StoredDestinationProgress {
  const progress = (existing.destinationProgress ??= {});
  const entry = (progress[key] ??= {
    phase: destination.phase,
    userId: destination.userId,
    deviceId: destination.deviceId,
    postMessageId: destination.postMessageId,
    state: 'pending',
    requests: 0,
    ...(!existing.progressFromStart && { uncertain: true as const }),
  });
  entry.postMessageId = destination.postMessageId;
  return entry;
}

/**
 * Mark the progress entry of a device that a repair gave a new message,
 * with the recovery that the repair ran and the ID of the new message. When
 * `replaced` is true, the repair replaced the message of the device, and the
 * entry also gets `repaired`. An earlier `repaired` mark stays.
 */
function markOutgoingDestinationRepaired(
  existing: StoredOutgoingMessageIntent,
  phase: StoredDestinationProgress['phase'],
  message: StoredOutgoingDeviceMessage,
  recovery: NonNullable<StoredDestinationProgress['repairedFor']>['recovery'],
  replaced: boolean
): void {
  const device = { userId: message.recipientUserId, deviceId: message.recipientDeviceId };
  const postMessageId = message.clientMessageId ?? existing.clientMessageId;
  const entry = outgoingDestinationProgressEntry(
    existing,
    outgoingDestinationProgressKey(postMessageId, device),
    { phase, ...device, postMessageId }
  );
  if (replaced) entry.repaired = true;
  entry.repairedFor = { recovery, postMessageId };
}

/**
 * True when a refusal of `entry` refuses its repair: the refused post is
 * the repaired message, and the kind of the refusal is the one that the
 * recovery of the repair answers. A stale-device repair answers
 * `STALE_DEVICE` and `device-rejection`, and a device-set repair answers
 * `device-set`. An entry with `repaired` and no stored recovery counts each
 * refusal. An entry with a stored recovery and no `repaired` mark (an added
 * device) reads the same rule.
 */
function refusesRepair(
  entry: StoredDestinationProgress,
  postMessageId: string,
  refusalCode: string | undefined
): boolean {
  const repair = entry.repairedFor;
  if (!repair) return entry.repaired === true;
  if (repair.postMessageId !== postMessageId) return false;
  return repair.recovery === 'device-set'
    ? refusalCode === 'device-set'
    : refusalCode === 'STALE_DEVICE' || refusalCode === 'device-rejection';
}

/** One request or one answer of one destination, as a progress write stores it. */
export type OutgoingDestinationProgressUpdate = Pick<
  StoredDestinationProgress,
  'phase' | 'userId' | 'deviceId' | 'postMessageId'
> &
  (
    | { readonly request: true }
    | ({
        readonly answer: 'accepted' | 'refused' | 'pending' | 'unknown';
        readonly repairSpent?: true;
      } & Pick<
        StoredDestinationProgress,
        'refusalCode' | 'messageId' | 'enqueuedAt' | 'expiresAt' | 'duplicate'
      >)
  );

/**
 * Merge one request or one answer into a progress entry, by the rules of
 * `recordOutgoingDestinationProgress`.
 */
function applyDestinationUpdate(
  entry: StoredDestinationProgress,
  update: OutgoingDestinationProgressUpdate
): void {
  if ('request' in update) {
    if (entry.state === 'posted') entry.uncertain = true;
    if (entry.state !== 'accepted') {
      entry.state = 'posted';
      delete entry.refusalCode;
    }
    entry.requests += 1;
    return;
  }
  if (entry.state === 'accepted') return;
  entry.state = update.answer;
  if (update.answer === 'unknown') entry.uncertain = true;
  if (update.answer !== 'refused') delete entry.refusalCode;
  if (update.answer === 'refused') {
    if (update.refusalCode === undefined) delete entry.refusalCode;
    else entry.refusalCode = update.refusalCode;
    if (update.repairSpent || refusesRepair(entry, update.postMessageId, update.refusalCode)) {
      entry.repairSpent = true;
    }
  }
  if (update.answer === 'accepted') {
    if (update.messageId !== undefined) entry.messageId = update.messageId;
    if (update.enqueuedAt !== undefined) entry.enqueuedAt = update.enqueuedAt;
    if (update.expiresAt !== undefined) entry.expiresAt = update.expiresAt;
    if (update.duplicate) entry.duplicate = true;
  }
}

/**
 * Record one request or one answer of one destination of an open intent,
 * and merge it into the entry under `key`.
 *
 * - Before each request, the entry becomes `posted` and its `requests` count
 *   grows by one. When the entry is already `posted`, an earlier request
 *   has no answer, so the entry becomes uncertain.
 * - After an answer, the entry takes the class of the answer. An uncertain
 *   answer sets `uncertain`. A refusal stores its code. A refusal that
 *   refuses the repair of the entry (`refusesRepair`) stores `repairSpent`.
 *   An `accepted` entry stays accepted.
 * - The refusal code belongs to the last answer, so a later request or a
 *   later answer that is not a refusal clears it. `repairSpent` stays: the
 *   refusal spent the repair, and a later answer does not give it back.
 *
 * The `uncertain` flag is never cleared. A completed or ended intent takes
 * no write, except a sync entry of a completed intent with `syncPending`.
 * The caller holds the intent lock, so this takes only the store mutation
 * order.
 *
 * @returns The stored entry, or undefined when nothing was written
 */
export async function recordOutgoingDestinationProgress(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  key: string,
  update: OutgoingDestinationProgressUpdate
): Promise<StoredDestinationProgress | undefined> {
  return serializeMutation(store, async () => {
    const intentKey = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(intentKey),
      null
    );
    if (!existing) {
      throw new Error('Cannot record the progress of a missing outgoing message intent');
    }
    const pendingSync = update.phase === 'sync' && existing.result && existing.syncPending;
    if ((existing.result || existing.outcome !== undefined) && !pendingSync) return undefined;

    const entry = outgoingDestinationProgressEntry(existing, key, update);
    applyDestinationUpdate(entry, update);
    stampOutgoingDeadline(existing);
    await store.setMetadata(intentKey, JSON.stringify(existing));
    return cloneReliabilityValue(entry);
  });
}

/**
 * The manual resends of an intent. An intent that an earlier SDK stored, or
 * that has no resend, has no `manualResends` field and reads as an empty
 * list.
 */
export function outgoingManualResends(
  intent: Pick<StoredOutgoingMessageIntent, 'manualResends'>
): StoredManualResend[] {
  return intent.manualResends ?? [];
}

/**
 * The time that the retention of an intent counts from: its `createdAt`, or
 * the `createdAt` of its latest manual resend. The ledger indexes the intent
 * at this time, so a manual resend keeps the intent, and its listing, for
 * `RELIABILITY_RECORD_TTL_MS` after the resend. That is past the posting
 * deadline of the resend.
 */
export function outgoingIntentRetainedFrom(
  intent: Pick<StoredOutgoingMessageIntent, 'createdAt' | 'manualResends'>
): number {
  return Math.max(
    intent.createdAt,
    ...outgoingManualResends(intent).map((resend) => resend.createdAt)
  );
}

/** True when a manual resend has neither a result nor an outcome. */
export function isOpenManualResend(resend: StoredManualResend): boolean {
  return resend.result === undefined && resend.outcome === undefined;
}

/**
 * The client message ID of manual resend number `n` of an intent, from 1.
 */
export function manualResendMessageId(clientMessageId: string, n: number): string {
  return `${clientMessageId}:manual:${String(n)}`;
}

/**
 * Store a new manual resend on an ended intent. The caller holds the intent
 * lock. Only an intent with `outcome` and no `result` takes one, and only
 * when no earlier resend of it is open. The intent keeps its own fields. The
 * ledger indexes the intent again at the `createdAt` of the resend, as
 * `outgoingIntentRetainedFrom` gives it. The new bucket is written before
 * the intent leaves its old bucket, so a stop leaves it in a bucket, and a
 * prune of the old bucket keeps an intent that the resend retains.
 */
export async function addOutgoingManualResend(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  resend: StoredManualResend,
  now = Date.now()
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.result || existing.outcome === undefined) {
      throw new Error('Only an ended outgoing message intent takes a manual resend');
    }
    const resends = outgoingManualResends(existing);
    if (resends.some(isOpenManualResend)) {
      throw new Error('An outgoing message intent has an open manual resend');
    }
    if (resend.manualMessageId !== manualResendMessageId(clientMessageId, resends.length + 1)) {
      throw new Error('A manual resend has the wrong message ID');
    }
    const retainedFrom = outgoingIntentRetainedFrom(existing);
    existing.manualResends = [...resends, cloneReliabilityValue(resend)];
    await store.setMetadata(key, JSON.stringify(existing));
    const indexTime = outgoingIntentRetainedFrom(existing);
    const retainedDays = await pruneExpiredBuckets(store, 'outbox', now);
    await indexRecord(store, 'outbox', clientMessageId, indexTime, retainedDays);
    if (dayFor(indexTime) !== dayFor(retainedFrom)) {
      await unindexRecord(store, 'outbox', clientMessageId, retainedFrom);
    }
    return cloneReliabilityValue(existing);
  });
}

/** The stored intent and the index of its manual resend, for a write under the store order. */
async function readManualResend(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  manualMessageId: string
): Promise<{ key: string; existing: StoredOutgoingMessageIntent; resend: StoredManualResend }> {
  const key = recordKey('outbox', clientMessageId);
  const existing = parseJson<StoredOutgoingMessageIntent | null>(await store.getMetadata(key), null);
  const resend = existing?.manualResends?.find(
    (candidate) => candidate.manualMessageId === manualMessageId
  );
  if (!existing || !resend) throw new Error('Cannot write a missing manual resend');
  return { key, existing, resend };
}

/**
 * Record one request or one answer of one destination of an open manual
 * resend, by the rules of `recordOutgoingDestinationProgress`. The resend
 * writes progress before each of its requests from its first write, so a
 * new entry starts with no uncertain request. An ended resend takes no
 * write.
 *
 * @returns The stored entry, or undefined when nothing was written
 */
export async function recordOutgoingManualResendProgress(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  manualMessageId: string,
  key: string,
  update: OutgoingDestinationProgressUpdate
): Promise<StoredDestinationProgress | undefined> {
  return serializeMutation(store, async () => {
    const read = await readManualResend(store, clientMessageId, manualMessageId);
    const { resend } = read;
    if (!isOpenManualResend(resend)) return undefined;
    const progress = (resend.destinationProgress ??= {});
    const entry = (progress[key] ??= {
      phase: update.phase,
      userId: update.userId,
      deviceId: update.deviceId,
      postMessageId: update.postMessageId,
      state: 'pending',
      requests: 0,
    });
    entry.postMessageId = update.postMessageId;
    applyDestinationUpdate(entry, update);
    await store.setMetadata(read.key, JSON.stringify(read.existing));
    return cloneReliabilityValue(entry);
  });
}

/**
 * End an open manual resend: with its Relay result when the Relay accepted
 * each of its destinations, else with its outcome. One write stores the end
 * and `outcomeReportedAt`, so the end is reported at most once. Each entry
 * of `destinationProgress` replaces the stored entry under its key.
 *
 * @returns The ended resend, or undefined when it had already ended
 */
export async function endOutgoingManualResend(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  manualMessageId: string,
  end:
    | { result: NonNullable<StoredOutgoingMessageIntent['result']> }
    | {
        outcome: NonNullable<StoredOutgoingMessageIntent['outcome']>;
        destinationProgress: Record<string, StoredDestinationProgress>;
      },
  at = Date.now()
): Promise<StoredManualResend | undefined> {
  return serializeMutation(store, async () => {
    const read = await readManualResend(store, clientMessageId, manualMessageId);
    const { resend } = read;
    if (!isOpenManualResend(resend)) return undefined;
    if ('result' in end) {
      resend.result = cloneReliabilityValue(end.result);
    } else {
      resend.outcome = end.outcome;
      resend.destinationProgress = {
        ...resend.destinationProgress,
        ...cloneReliabilityValue(end.destinationProgress),
      };
    }
    resend.outcomeReportedAt = at;
    await store.setMetadata(read.key, JSON.stringify(read.existing));
    return cloneReliabilityValue(resend);
  });
}

function outgoingMessageDeviceKey(message: StoredOutgoingDeviceMessage): string {
  return outgoingDeviceKey({
    userId: message.recipientUserId,
    deviceId: message.recipientDeviceId,
  });
}

/**
 * The messages with each new message appended once. A stored message of the
 * same device must be equal to the new message.
 */
function appendOutgoingDeviceMessages(
  messages: StoredOutgoingDeviceMessage[],
  additions: readonly StoredOutgoingDeviceMessage[],
  refusal = 'Cannot replace a persisted group transmission'
): StoredOutgoingDeviceMessage[] {
  for (const message of additions) {
    const prior = messages.find(
      (candidate) => outgoingMessageDeviceKey(candidate) === outgoingMessageDeviceKey(message)
    );
    if (prior) {
      if (JSON.stringify(prior) !== JSON.stringify(message)) {
        throw new Error(refusal);
      }
      continue;
    }
    messages.push(cloneReliabilityValue(message));
  }
  return messages;
}

/**
 * Remove the pre-messages that the relay accepted or that the send dropped
 * from a group intent, so a replay posts only the pre-messages that the relay
 * did not accept. Each device in `removedDevices` loses all of its messages
 * in the same write.
 */
export async function confirmOutgoingPreMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  acceptedClientMessageIds: readonly string[],
  removedDevices: readonly OutgoingGroupDevice[] = []
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'group' || existing.result) {
      throw new Error('Cannot confirm pre-messages of a missing or completed group outbox intent');
    }

    const accepted = new Set(acceptedClientMessageIds);
    const removed = new Set(removedDevices.map(outgoingDeviceKey));
    const kept = (messages: readonly StoredOutgoingDeviceMessage[]) =>
      messages.filter((message) => !removed.has(outgoingMessageDeviceKey(message)));
    const remaining = kept(existing.preMessages ?? []).filter(
      (message) => message.clientMessageId === undefined || !accepted.has(message.clientMessageId)
    );
    existing.deviceMessages = kept(existing.deviceMessages);
    existing.syncMessages = kept(existing.syncMessages);
    if (remaining.length > 0) existing.preMessages = remaining;
    else delete existing.preMessages;

    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Replace stored pre-messages of a group intent in one write. Each
 * replacement keeps the target and the timestamp of the pre-message that it
 * replaces, and the stored pre-message must still equal the expected one. A
 * replacement under a new client message ID is a repair: its progress entry
 * gets `repaired`, and the write creates the entry when none exists. A
 * replacement under the same ID, such as the sealed form of the stored
 * pre-message, gets no mark.
 */
export async function replaceOutgoingGroupPreMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  replacements: readonly {
    expected: StoredOutgoingDeviceMessage;
    replacement: StoredOutgoingDeviceMessage;
  }[]
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'group' || existing.result) {
      throw new Error('Cannot replace pre-messages of a missing or completed group outbox intent');
    }

    const preMessages = existing.preMessages ?? [];
    for (const { expected, replacement } of replacements) {
      const index = preMessages.findIndex(
        (candidate) =>
          candidate.recipientUserId === expected.recipientUserId &&
          candidate.recipientDeviceId === expected.recipientDeviceId
      );
      if (index < 0 || JSON.stringify(preMessages[index]) !== JSON.stringify(expected)) {
        throw new Error('Cannot replace an unexpected group pre-message');
      }
      if (
        replacement.recipientUserId !== expected.recipientUserId ||
        replacement.recipientDeviceId !== expected.recipientDeviceId ||
        replacement.timestamp !== expected.timestamp
      ) {
        throw new Error('A group pre-message replacement cannot change its target or timestamp');
      }
      if (replacement.clientMessageId !== expected.clientMessageId) {
        markOutgoingDestinationRepaired(existing, 'recipient', replacement, 'stale-device', true);
      }
      preMessages[index] = cloneReliabilityValue(replacement);
    }

    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Apply the recipient's device list to a direct intent in one write: remove
 * the messages of the devices that the list no longer shows, append a message
 * for each newly listed device, and clear the pending reconcile.
 */
export async function reconcileOutgoingDirectDeviceMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  removedDeviceIds: readonly number[],
  messages: StoredOutgoingDeviceMessage[]
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'direct' || existing.result) {
      throw new Error('Cannot reconcile a missing or completed direct outbox intent');
    }

    existing.deviceMessages = existing.deviceMessages.filter(
      (candidate) => !removedDeviceIds.includes(candidate.recipientDeviceId)
    );
    for (const message of messages) {
      if (message.recipientUserId !== existing.recipientId) {
        throw new Error('A direct outbox intent cannot address another recipient');
      }
      const prior = existing.deviceMessages.find(
        (candidate) => candidate.recipientDeviceId === message.recipientDeviceId
      );
      if (prior) {
        if (JSON.stringify(prior) !== JSON.stringify(message)) {
          throw new Error('Cannot replace a persisted direct transmission');
        }
        continue;
      }
      existing.deviceMessages.push(cloneReliabilityValue(message));
    }
    delete existing.reconcilePending;

    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Change the sync copies of a direct or group intent in one write. The sync
 * copies of each removed own device leave the intent first. Then each new
 * sync copy is appended. A new copy for a device that still has a copy must
 * be equal to it, and is not appended again. A completed intent accepts the
 * change only while its sync phase is pending.
 */
export async function reconcileOutgoingSyncMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  removedDeviceIds: readonly number[],
  additions: readonly StoredOutgoingDeviceMessage[]
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || (existing.result && !existing.syncPending)) {
      throw new Error('Cannot change the sync copies of a missing or completed outbox intent');
    }

    existing.syncMessages = appendOutgoingDeviceMessages(
      existing.syncMessages.filter(
        (message) => !removedDeviceIds.includes(message.recipientDeviceId)
      ),
      additions,
      'Cannot replace a persisted sync transmission'
    );
    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Replace the stored message of one device of an open direct intent after a
 * session repair. The progress entry of the device gets the repair mark.
 *
 * @returns The stored intent, with the progress entry of the device
 */
export async function replaceOutgoingDirectDeviceMessage(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  expected: StoredOutgoingDeviceMessage,
  replacement: StoredOutgoingDeviceMessage
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'direct' || existing.result) {
      throw new Error('Cannot repair a missing or completed direct outbox intent');
    }

    const index = existing.deviceMessages.findIndex(
      (candidate) =>
        candidate.recipientUserId === expected.recipientUserId &&
        candidate.recipientDeviceId === expected.recipientDeviceId
    );
    if (index < 0 || JSON.stringify(existing.deviceMessages[index]) !== JSON.stringify(expected)) {
      throw new Error('Cannot replace an unexpected direct outbox transmission');
    }
    if (
      replacement.recipientUserId !== expected.recipientUserId ||
      replacement.recipientDeviceId !== expected.recipientDeviceId ||
      replacement.timestamp !== expected.timestamp
    ) {
      throw new Error('A direct outbox repair cannot change its target or timestamp');
    }

    existing.deviceMessages[index] = cloneReliabilityValue(replacement);
    markOutgoingDestinationRepaired(existing, 'recipient', replacement, 'stale-device', true);
    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

export async function getOutgoingMessageIntent(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  now = Date.now()
): Promise<StoredOutgoingMessageIntent | null> {
  const record = parseJson<StoredOutgoingMessageIntent | null>(
    await store.getMetadata(recordKey('outbox', clientMessageId)),
    null
  );
  if (!record || outgoingIntentRetainedFrom(record) < now - RELIABILITY_RECORD_TTL_MS) return null;
  return cloneReliabilityValue(record);
}

export async function storeOutgoingMessageIntent(
  store: ReliabilityMetadataStore,
  intent: StoredOutgoingMessageIntent,
  now = Date.now()
): Promise<void> {
  await serializeMutation(store, async () => {
    const retainedDays = await pruneExpiredBuckets(store, 'outbox', now);
    const key = recordKey('outbox', intent.clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    const retainedExisting =
      existing && outgoingIntentRetainedFrom(existing) >= now - RELIABILITY_RECORD_TTL_MS
        ? existing
        : null;
    if (retainedExisting && !sameIntent(retainedExisting, intent)) {
      throw new Error('A clientMessageId cannot identify two different encrypted sends');
    }
    if (!retainedExisting) {
      await store.setMetadata(key, JSON.stringify(intent));
      await indexSentTimestamp(store, intent, now);
    } else {
      // A failed index write after the intent write leaves the retained
      // intent without its timestamp lookup. The same intent repairs only
      // that index, under the retained creation time.
      await indexSentTimestamp(store, retainedExisting, now);
    }
    await indexRecord(
      store,
      'outbox',
      intent.clientMessageId,
      outgoingIntentRetainedFrom(retainedExisting ?? intent),
      retainedDays
    );
  });
}

/**
 * Index the client message ID of an intent under its client timestamp,
 * the value by which an E2EE receipt names the message. The index expires
 * with the intent. A second call for the same intent changes no entry.
 */
async function indexSentTimestamp(
  store: ReliabilityMetadataStore,
  intent: StoredOutgoingMessageIntent,
  now: number
): Promise<void> {
  const retainedDays = await pruneExpiredBuckets(store, 'sent-timestamp', now);
  const id = String(intent.clientTimestamp);
  const key = recordKey('sent-timestamp', id);
  const clientMessageIds = parseJson<string[]>(await store.getMetadata(key), []);
  if (!clientMessageIds.includes(intent.clientMessageId)) {
    clientMessageIds.push(intent.clientMessageId);
    await store.setMetadata(key, JSON.stringify(clientMessageIds));
  }
  await indexRecord(store, 'sent-timestamp', id, intent.createdAt, retainedDays);
}

/**
 * The client message IDs of the intents with this client timestamp. More
 * than one intent can have the same timestamp, so the caller matches the
 * recipient.
 */
export async function getSentClientMessageIds(
  store: ReliabilityMetadataStore,
  clientTimestamp: number
): Promise<string[]> {
  return parseJson<string[]>(
    await store.getMetadata(recordKey('sent-timestamp', String(clientTimestamp))),
    []
  );
}

/**
 * The key of one received message: its sender device, its content timestamp
 * and the digest of its content. A manual resend of a sender has a new
 * envelope ID and keeps the content timestamp and the content, so the key
 * finds a copy that the envelope ID does not. The digest keeps two messages
 * that one sender device sent in the same millisecond apart. The record of
 * a key expires after `RETRY_REQUESTER_RECORD_TTL_MS`: a sender posts its
 * last manual resend at most `RELIABILITY_RECORD_TTL_MS` after the intent,
 * and the Relay keeps a post for at most `RELIABILITY_RECORD_TTL_MS`.
 */
export interface ReceivedMessageKey {
  readonly senderUserId: string;
  /**
   * The device ID of the sender.
   *
   * @deprecated The next major SDK version removes the sender device from
   *   the key. A key then holds only the sender user and the timestamp, so
   *   the recipient also drops a later message from another device of the
   *   sender with the same timestamp. A custom store that checks or stores
   *   `ReceiveWorkRecord.received` must accept a key with no
   *   `senderDeviceId`.
   */
  readonly senderDeviceId: number;
  /** The content timestamp of the message. */
  readonly timestamp: number;
  /**
   * The base64 SHA-256 of the UTF-8 bytes of the content that the
   * application gets, with no group context in it.
   *
   * @deprecated The next major SDK version removes the digest from the key.
   *   In SDK 13.x, two different messages of one sender device with one
   *   timestamp both deliver. In the next major SDK version, the recipient
   *   keeps the first such message and drops a later one with no notice. A
   *   custom store that checks or stores `ReceiveWorkRecord.received` must
   *   accept a key with no `contentDigest`.
   */
  readonly contentDigest: string;
}

/** The record ID of one received message. */
function receivedMessageId(key: ReceivedMessageKey): string {
  return JSON.stringify([key.senderUserId, key.senderDeviceId, key.timestamp, key.contentDigest]);
}

/**
 * True when the local device processed a message with this key. The record
 * expires after `RETRY_REQUESTER_RECORD_TTL_MS`.
 */
export async function hasReceivedTimestamp(
  store: ReliabilityMetadataStore,
  key: ReceivedMessageKey
): Promise<boolean> {
  const value = await store.getMetadata(recordKey('received-timestamp', receivedMessageId(key)));
  return value !== null;
}

/** Write the record of one received message. The caller serializes the write. */
async function writeReceivedTimestamp(
  store: ReliabilityMetadataStore,
  key: ReceivedMessageKey,
  now: number
): Promise<void> {
  const retainedDays = await pruneExpiredBuckets(store, 'received-timestamp', now);
  const id = receivedMessageId(key);
  await store.setMetadata(recordKey('received-timestamp', id), JSON.stringify({ receivedAt: now }));
  await indexRecord(store, 'received-timestamp', id, now, retainedDays);
}

/**
 * Record that the local device processed a message with this key. The
 * record expires after `RETRY_REQUESTER_RECORD_TTL_MS`. A receive that completes
 * its record writes the key with `completeReceiveRecord` instead.
 */
export async function recordReceivedTimestamp(
  store: ReliabilityMetadataStore,
  key: ReceivedMessageKey,
  now = Date.now()
): Promise<void> {
  await serializeMutation(store, () => writeReceivedTimestamp(store, key, now));
}

/** A source that tells that a recipient device has a message. */
export type StoredDeliverySource = 'relay' | 'e2ee';

/** The delivery of one message to one recipient device. */
export interface StoredDeviceDelivery {
  /** Each source of the delivery, once, in the order of arrival. */
  sources: StoredDeliverySource[];
  /** The time of the first source, in epoch milliseconds. */
  deliveredAt: number;
  /** The number of leading `sources` that the client announced. */
  announced: number;
}

/** The delivery status of one outgoing message, by recipient user and device. */
export interface StoredDeliveryStatus {
  clientMessageId: string;
  /** The creation time of the intent. The status expires with the intent. */
  createdAt: number;
  devices: Record<string, Record<string, StoredDeviceDelivery>>;
}

/**
 * Read and change the delivery status of one outgoing message in one
 * serialized step. The step also reads the outbox intent, so an intent that
 * completes during a receipt is seen by either the receipt or the next
 * step. `update` changes `status` in place. A changed status is written.
 * Resolves to undefined, and changes nothing, when no intent of this client
 * message ID counts.
 */
export async function updateDeliveryStatus<T>(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  update: (status: StoredDeliveryStatus, intent: StoredOutgoingMessageIntent) => T,
  now = Date.now()
): Promise<T | undefined> {
  return serializeMutation(store, async () => {
    const intent = await getOutgoingMessageIntent(store, clientMessageId, now);
    if (!intent) return undefined;
    const key = recordKey('delivery-status', clientMessageId);
    const stored = parseJson<StoredDeliveryStatus | null>(await store.getMetadata(key), null);
    const status: StoredDeliveryStatus =
      stored && stored.createdAt === intent.createdAt
        ? stored
        : { clientMessageId, createdAt: intent.createdAt, devices: {} };
    const before = JSON.stringify(status);
    const value = update(status, intent);
    if (JSON.stringify(status) !== before) {
      const retainedDays = await pruneExpiredBuckets(store, 'delivery-status', now);
      await store.setMetadata(key, JSON.stringify(status));
      await indexRecord(store, 'delivery-status', clientMessageId, status.createdAt, retainedDays);
    }
    return value;
  });
}

/**
 * Complete an outgoing intent with its Relay result. With `syncPending`,
 * the recipient phase completed and the sync phase did not: the intent keeps
 * its sync messages and the restart count of its sync phase, so a replay
 * posts only the sync messages. With `syncPending` and no sync messages, the
 * read of the own device list failed, and a replay reads it. The intent
 * keeps `destinationProgress`.
 */
export async function completeOutgoingMessageIntent(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  result: NonNullable<StoredOutgoingMessageIntent['result']>,
  options: { syncPending?: boolean } = {}
): Promise<void> {
  await serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing) throw new Error('Cannot complete a missing outgoing message intent');
    if (existing.result && JSON.stringify(existing.result) !== JSON.stringify(result)) {
      throw new Error('Cannot replace an outgoing message intent with a different Relay result');
    }
    const report = existing.result ? undefined : outgoingIntentEndReport(store, clientMessageId);
    if (report?.driven && !existing.internal) existing.outcomeReportPending = true;
    existing.result = cloneReliabilityValue(result);
    delete existing.reconcilePending;
    delete existing.preMessages;
    existing.deviceMessages = [];
    if (options.syncPending) {
      existing.syncPending = true;
      const sync = existing.deviceSetRestarts?.sync;
      if (sync === undefined) delete existing.deviceSetRestarts;
      else existing.deviceSetRestarts = { sync };
      if (existing.deviceSetUnresolved?.phase !== 'sync') delete existing.deviceSetUnresolved;
      const syncMissing = existing.deviceSetBundleMissing?.sync;
      if (syncMissing) existing.deviceSetBundleMissing = { sync: syncMissing };
      else delete existing.deviceSetBundleMissing;
    } else {
      existing.syncMessages = [];
      delete existing.syncPending;
      delete existing.deviceSetRestarts;
      delete existing.deviceSetUnresolved;
      delete existing.deviceSetBundleMissing;
    }
    delete existing.sealedSenderAuth;
    delete existing.groupCiphertext;
    delete existing.groupSenderKeyDistributionId;
    delete existing.groupSharedMessage;
    await store.setMetadata(key, JSON.stringify(existing));
    if (report) report.ended = cloneReliabilityValue(existing);
  });
}

/**
 * End an open intent at its posting deadline. It keeps the device messages
 * and every other field, and it stores the posting deadline. Each entry of
 * `destinationProgress` replaces the stored entry under its key, and each
 * other stored entry stays. A completed
 * intent keeps its `result`, which takes precedence, and this writes nothing.
 * An intent that ended with another outcome is refused.
 */
export async function endOutgoingMessageIntent(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  end: {
    outcome: NonNullable<StoredOutgoingMessageIntent['outcome']>;
    destinationProgress: Record<string, StoredDestinationProgress>;
  }
): Promise<void> {
  await serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing) throw new Error('Cannot end a missing outgoing message intent');
    if (existing.result) return;
    if (existing.outcome !== undefined && existing.outcome !== end.outcome) {
      throw new Error('Cannot end an outgoing message intent with a different outcome');
    }
    const report =
      existing.outcome === undefined ? outgoingIntentEndReport(store, clientMessageId) : undefined;
    if (report?.driven && !existing.internal) existing.outcomeReportPending = true;
    existing.outcome = end.outcome;
    existing.destinationProgress = {
      ...existing.destinationProgress,
      ...cloneReliabilityValue(end.destinationProgress),
    };
    stampOutgoingDeadline(existing);
    await store.setMetadata(key, JSON.stringify(existing));
    if (report) report.ended = cloneReliabilityValue(existing);
  });
}

/** The key prefix of the outgoing intent records. */
const OUTGOING_INTENT_RECORD_PREFIX = `${OUTBOX_PREFIX}:record:`;

/** The keys of one listing page of the outgoing intent records. */
const OUTGOING_INTENT_PAGE_SIZE = 100;

/** The intent of the record under `key`, or null for a value that is not an intent. */
function parseOutgoingIntentRecord(
  key: string,
  value: string | null
): StoredOutgoingMessageIntent | null {
  try {
    const clientMessageId = decodeURIComponent(key.slice(OUTGOING_INTENT_RECORD_PREFIX.length));
    const record = parseJson<Partial<StoredOutgoingMessageIntent> | null>(value, null);
    if (
      record === null ||
      typeof record !== 'object' ||
      (record.kind !== 'direct' && record.kind !== 'group') ||
      record.clientMessageId !== clientMessageId ||
      typeof record.recipientId !== 'string' ||
      typeof record.plaintextDigest !== 'string' ||
      !Number.isFinite(record.clientTimestamp) ||
      !Number.isFinite(record.createdAt) ||
      !Array.isArray(record.deviceMessages) ||
      !Array.isArray(record.syncMessages)
    ) {
      return null;
    }
    return record as StoredOutgoingMessageIntent;
  } catch {
    return null;
  }
}

/**
 * Every stored outgoing intent, in the key order of the store, or undefined
 * when the store does not implement `listMetadataKeys`. It skips a value
 * that is not an intent. It lists exactly the record prefix of the outbox,
 * so the bucket and manifest rows of the outbox stay out.
 */
async function scanOutgoingIntentRecords(
  store: ReliabilityMetadataStore
): Promise<StoredOutgoingMessageIntent[] | undefined> {
  if (typeof store.listMetadataKeys !== 'function') return undefined;
  const intents: StoredOutgoingMessageIntent[] = [];
  let after: string | undefined;
  for (;;) {
    const keys = await store.listMetadataKeys({
      prefix: OUTGOING_INTENT_RECORD_PREFIX,
      ...(after !== undefined && { after }),
      limit: OUTGOING_INTENT_PAGE_SIZE,
    });
    for (const key of keys) {
      if (!key.startsWith(OUTGOING_INTENT_RECORD_PREFIX)) continue;
      if (after !== undefined && key <= after) continue;
      const intent = parseOutgoingIntentRecord(key, await store.getMetadata(key));
      if (intent) intents.push(intent);
    }
    const last = keys[keys.length - 1];
    // A page that ends at or below `after` would list the same keys again.
    if (keys.length < OUTGOING_INTENT_PAGE_SIZE || (after !== undefined && last <= after)) {
      return intents;
    }
    after = last;
  }
}

/**
 * The outgoing intents that the SDK send driver acts on, or undefined when
 * the store does not implement `listMetadataKeys`. It returns each intent
 * whose `outgoingIntentRetainedFrom` is not older than
 * `RELIABILITY_RECORD_TTL_MS` and that is open (no
 * `result` and no `outcome`), holds `outcomeReportPending`, or holds a
 * manual resend with no `result` and no `outcome` of its own.
 */
export async function listOpenOutgoingIntents(
  store: ReliabilityMetadataStore,
  now = Date.now()
): Promise<StoredOutgoingMessageIntent[] | undefined> {
  const intents = await scanOutgoingIntentRecords(store);
  if (intents === undefined) return undefined;
  return intents.filter(
    (intent) =>
      outgoingIntentRetainedFrom(intent) >= now - RELIABILITY_RECORD_TTL_MS &&
      ((!intent.result && intent.outcome === undefined) ||
        intent.outcomeReportPending === true ||
        outgoingManualResends(intent).some(isOpenManualResend))
  );
}

/**
 * Clear `outcomeReportPending` on an intent and record the time of the
 * report. The SDK send driver calls it before it calls `onSendOutcome`, and
 * calls the hook only when it returns true. It reads the record again under
 * the intent lock, so of two drivers on one store, only one clears the mark.
 * It returns false, and writes nothing, for an intent without the field.
 */
export async function markOutgoingIntentReported(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  at = Date.now()
): Promise<boolean> {
  return withOutgoingMessageIntentLock(store, clientMessageId, () =>
    serializeMutation(store, async () => {
      const key = recordKey('outbox', clientMessageId);
      const existing = parseJson<StoredOutgoingMessageIntent | null>(
        await store.getMetadata(key),
        null
      );
      if (!existing?.outcomeReportPending) return false;
      delete existing.outcomeReportPending;
      existing.outcomeReportedAt = at;
      await store.setMetadata(key, JSON.stringify(existing));
      return true;
    })
  );
}

/**
 * Store the posting deadline on each open outgoing intent that an earlier
 * SDK stored without one. The deadline comes from the stored times, as
 * `outgoingMessageDeadlineAt` computes it, so the moved deadline is the one
 * that the intent already had. It writes no report field, so the SDK send
 * driver reports no end that an earlier SDK wrote. With a store that does
 * not implement `listMetadataKeys`, or with no open intent without a
 * deadline, it writes nothing. Such an intent then gets its deadline at its
 * next mutation write.
 */
export async function migrateOutgoingIntentRecords(
  store: ReliabilityMetadataStore,
  now = Date.now()
): Promise<void> {
  const intents = await listOpenOutgoingIntents(store, now);
  const unstamped = (intents ?? []).filter(
    (intent) => !intent.result && intent.outcome === undefined && intent.deadlineAt === undefined
  );
  if (unstamped.length === 0) return;
  await serializeMutation(store, async () => {
    for (const intent of unstamped) {
      const key = recordKey('outbox', intent.clientMessageId);
      const existing = parseOutgoingIntentRecord(key, await store.getMetadata(key));
      if (
        !existing ||
        existing.result ||
        existing.outcome !== undefined ||
        existing.deadlineAt !== undefined
      ) {
        continue;
      }
      stampOutgoingDeadline(existing);
      if (existing.deadlineAt === undefined) continue;
      await store.setMetadata(key, JSON.stringify(existing));
    }
  });
}

/** The record of one envelope ID that the local device processed. */
export interface ProcessedEnvelope {
  /** The time of the processing. The record expires from this time. */
  processedAt: number;
  /** The fingerprint of the processed envelope. */
  fingerprint?: string;
  /**
   * True when the application got the content of this failed envelope,
   * from the envelope itself or from a resend. The requester then drops
   * each later member of its retry family.
   */
  fulfilled?: true;
  /**
   * True when the application finished the content of this failed envelope:
   * the receive record of its resend completed. `onDeliveryRecovered` waits
   * for this fact, not for `fulfilled`.
   */
  completed?: true;
  /**
   * The end of a receive record that the application never got: `denied`
   * after a refusal, `expired` after 30 days of waiting or after
   * `discardPendingReceive`.
   */
  outcome?: ProcessedEnvelopeOutcome;
}

/** The end of a receive record that the application never got. */
export type ProcessedEnvelopeOutcome = 'denied' | 'expired';

/** The fields of one processed-envelope write. */
export interface ProcessedEnvelopeWrite {
  envelopeId: string;
  fingerprint?: string;
  fulfilled?: true;
  completed?: true;
  outcome?: ProcessedEnvelopeOutcome;
}

/** The record of one received message, written with the completion of its receive. */
export interface ReceivedTimestampWrite {
  receivedMessage: ReceivedMessageKey;
}

/** One write of a receive completion. */
export type ReceiveCompletionWrite = ProcessedEnvelopeWrite | ReceivedTimestampWrite;

/** The lifetime of one processed-envelope record. */
function processedEnvelopeTtl(record: ProcessedEnvelope): number {
  return record.fulfilled || record.completed
    ? RETRY_REQUESTER_RECORD_TTL_MS
    : RELIABILITY_RECORD_TTL_MS;
}

/**
 * The time that the incoming ledger indexes one record at. The ledger
 * prunes a day after `RELIABILITY_RECORD_TTL_MS`, so a fulfilled record
 * goes to a later day and lives for `RETRY_REQUESTER_RECORD_TTL_MS`.
 */
function processedEnvelopeIndexTime(record: ProcessedEnvelope): number {
  return record.processedAt + processedEnvelopeTtl(record) - RELIABILITY_RECORD_TTL_MS;
}

async function readProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string
): Promise<ProcessedEnvelope | null> {
  const value = await store.getMetadata(recordKey('incoming', envelopeId));
  if (value === null) return null;
  const { processedAt, fingerprint, fulfilled, completed, outcome } = JSON.parse(value);
  if (
    !Number.isFinite(processedAt) ||
    (fingerprint !== undefined && typeof fingerprint !== 'string') ||
    (fulfilled !== undefined && fulfilled !== true) ||
    (completed !== undefined && completed !== true) ||
    (outcome !== undefined && outcome !== 'denied' && outcome !== 'expired')
  ) {
    throw new Error('Corrupt processed-envelope record');
  }
  return {
    processedAt,
    ...(fingerprint !== undefined && { fingerprint }),
    ...(fulfilled === true && { fulfilled }),
    ...(completed === true && { completed }),
    ...(outcome !== undefined && { outcome }),
  };
}

/**
 * Get the processed-envelope record of one envelope ID. A record older
 * than `RELIABILITY_RECORD_TTL_MS` does not count. A fulfilled record
 * counts for `RETRY_REQUESTER_RECORD_TTL_MS`.
 */
export async function getProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  now = Date.now()
): Promise<ProcessedEnvelope | null> {
  const record = await readProcessedEnvelope(store, envelopeId);
  if (record === null) return null;
  if (record.processedAt < now - processedEnvelopeTtl(record)) return null;
  return record;
}

/**
 * Tell whether the local device processed one envelope ID. A record counts
 * for the lifetime that `getProcessedEnvelope` applies.
 */
export async function hasProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  now = Date.now()
): Promise<boolean> {
  return (await getProcessedEnvelope(store, envelopeId, now)) !== null;
}

/**
 * Record that the local device processed one envelope ID. The write keeps
 * the fingerprint, the flags, and the outcome of a record that counts, so a
 * later store for the same ID never clears them.
 *
 * @param fulfilled - True when the application got the content of this
 *   failed envelope. The processed fact and the fulfilled fact are then
 *   one write.
 */
export async function storeProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  processedAt = Date.now(),
  fingerprint?: string,
  fulfilled?: true
): Promise<void> {
  await serializeMutation(store, () =>
    writeProcessedEnvelope(store, processedAt, {
      envelopeId,
      ...(fingerprint !== undefined && { fingerprint }),
      ...(fulfilled && { fulfilled }),
    })
  );
}

/**
 * Write several processed-envelope records in one turn of the mutation
 * queue. A denial with no receive record uses it: the denied outcome and
 * the processed fact of the envelope land together.
 */
export async function writeProcessedEnvelopes(
  store: ReliabilityMetadataStore,
  writes: readonly ProcessedEnvelopeWrite[],
  processedAt = Date.now()
): Promise<void> {
  await serializeMutation(store, async () => {
    for (const write of writes) await writeProcessedEnvelope(store, processedAt, write);
  });
}

/** Write one processed-envelope record. The caller holds the mutation queue. */
async function writeProcessedEnvelope(
  store: ReliabilityMetadataStore,
  processedAt: number,
  write: ProcessedEnvelopeWrite
): Promise<void> {
  const { envelopeId } = write;
  const existing = await readProcessedEnvelope(store, envelopeId);
  const current =
    existing && existing.processedAt >= processedAt - processedEnvelopeTtl(existing)
      ? existing
      : null;
  const keptFingerprint = write.fingerprint ?? current?.fingerprint;
  const keptOutcome = write.outcome ?? current?.outcome;
  const record: ProcessedEnvelope = {
    processedAt,
    ...(keptFingerprint !== undefined && { fingerprint: keptFingerprint }),
    ...((write.fulfilled || current?.fulfilled) && { fulfilled: true as const }),
    ...((write.completed || current?.completed) && { completed: true as const }),
    ...(keptOutcome !== undefined && { outcome: keptOutcome }),
  };
  const indexTime = processedEnvelopeIndexTime(record);
  const retainedDays = await pruneExpiredBuckets(store, 'incoming', processedAt);
  await store.setMetadata(recordKey('incoming', envelopeId), JSON.stringify(record));
  await indexRecord(store, 'incoming', envelopeId, indexTime, retainedDays);
  // The bucket of the earlier record would prune the new record early.
  if (existing) {
    const existingIndexTime = processedEnvelopeIndexTime(existing);
    if (dayFor(existingIndexTime) !== dayFor(indexTime)) {
      await unindexRecord(store, 'incoming', envelopeId, existingIndexTime);
    }
  }
}

/**
 * Complete one receive record: delete it and write its processed-envelope
 * records and the record of its received message in one atomic store write.
 * The writes run against a buffer over the store, so the ledger index and the
 * records commit with the delete or not at all.
 *
 * @returns False, with nothing written, when the stored revision of the
 *   receive record is not `expectedRevision`.
 */
export async function completeReceiveRecord(
  store: ReliabilityMetadataStore & Pick<SignalProtocolLocalStore, 'completeReceiveWork'>,
  workId: string,
  expectedRevision: number,
  writes: readonly ReceiveCompletionWrite[],
  processedAt = Date.now()
): Promise<boolean> {
  return serializeMutation(store, async () => {
    const buffer = new Map<string, string | null>();
    const buffered: ReliabilityMetadataStore = {
      getMetadata: async (key) => (buffer.has(key) ? buffer.get(key)! : store.getMetadata(key)),
      setMetadata: async (key, value) => {
        buffer.set(key, value);
      },
      deleteMetadata: async (key) => {
        buffer.set(key, null);
      },
    };
    for (const write of writes) {
      if ('receivedMessage' in write) {
        await writeReceivedTimestamp(buffered, write.receivedMessage, processedAt);
      } else {
        await writeProcessedEnvelope(buffered, processedAt, write);
      }
    }
    return store.completeReceiveWork(
      workId,
      expectedRevision,
      [...buffer].map(([key, value]) => ({ key, value }))
    );
  });
}

/**
 * The relay gave a failed envelope ID again with other content after the
 * local device stored a retry request for that ID.
 */
export class RetryRequestedEnvelopeChangedError extends Error {
  constructor() {
    super('Relay envelope identity changed after the retry request');
    this.name = 'RetryRequestedEnvelopeChangedError';
  }
}

/**
 * The retry ID shape: a UUID in lowercase hex. The requester makes one
 * retry ID for each retry request record, and every wire ID of that retry
 * family derives from it.
 */
const RETRY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** Tell whether a value has the shape of a retry ID. */
export function isRetryId(value: unknown): value is string {
  return typeof value === 'string' && RETRY_ID.test(value);
}

/**
 * The client message ID of the retry request with one retry ID. The first
 * attempt of that request posts under this ID.
 */
export function retryRequestClientMessageId(retryId: string): string {
  return `${retryId}:retry-request`;
}

/**
 * The resend ID of the content resend for one retry ID. The first attempt of
 * that resend posts under this ID.
 */
export function retryResendClientMessageId(retryId: string): string {
  return `${retryId}:resend`;
}

/**
 * The resend ID of the null message for one retry ID. It is not the content
 * resend ID, so a null message never posts content bytes.
 */
export function retryNullMessageClientMessageId(retryId: string): string {
  return `${retryId}:null`;
}

/**
 * The client message ID of one attempt of a retry request or a retry resend.
 * Attempt 1 posts under the given ID, and attempt `n` posts under
 * `<id>:<n>`. A resend takes the attempt number of the request that it
 * answers. Each attempt ID gets one encryption. When the Relay refuses the
 * stored bytes of an attempt with OPERATION_EXPIRED, the attempt is marked
 * acceptance-unknown, and nothing more posts under its ID.
 */
export function retryAttemptClientMessageId(id: string, attempt: number): string {
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new Error('A retry attempt is a positive integer');
  }
  return attempt === 1 ? id : `${id}:${attempt}`;
}

const RETRY_FAMILY_ENVELOPE_ID =
  /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(retry-request|resend|null)(?::([2-9]|[1-9][0-9]+))?$/u;

/**
 * The two IDs that a retry request payload carries: the failed envelope and
 * the retry ID of the request record. The resend and the null message IDs
 * derive from the retry ID and from the attempt number of the request
 * envelope that they answer.
 */
export interface RetryRequestIds {
  /** The Relay message ID of the envelope that the requester could not decrypt. */
  failedEnvelopeId: string;
  /** The retry ID of the request record. */
  retryId: string;
}

/** An envelope ID that one retry ID derives. */
export interface RetryFamilyMember {
  /** The retry ID: the family key on the wire. */
  retryId: string;
  /** The retry request, the content resend or the null message. */
  kind: 'retry-request' | 'resend' | 'null';
  /** The attempt number of the ID, from 1. */
  attempt: number;
}

/**
 * The retry ID, the kind and the attempt number of an envelope whose ID has
 * the shape of a retry attempt: `<retryId>:retry-request[:n]`,
 * `<retryId>:resend[:n]` or `<retryId>:null[:n]`, with `n` from 2. An ID
 * with no `n` is attempt 1. Undefined for any other ID. Only the family
 * index of the requester tells which failed envelope a retry ID names.
 */
export function retryFamilyMember(envelopeId: string): RetryFamilyMember | undefined {
  const match = RETRY_FAMILY_ENVELOPE_ID.exec(envelopeId);
  if (!match) return undefined;
  return {
    retryId: match[1]!,
    kind: match[2] as RetryFamilyMember['kind'],
    attempt: match[3] === undefined ? 1 : Number(match[3]),
  };
}

/**
 * The attempt number of the retry request that a resend or a null message
 * answers, from the request envelope ID. The answer carries this number,
 * so the requester can tell which of its attempts the answer is for.
 * Throws when the ID is not a retry request of the retry ID: the requester
 * makes each request envelope ID, so the sender never answers another ID.
 */
export function retryRequestAttempt(
  target: Pick<RetryResendTarget, 'retryId' | 'requestEnvelopeId'>
): number {
  const member = retryFamilyMember(target.requestEnvelopeId);
  if (member?.kind !== 'retry-request' || member.retryId !== target.retryId) {
    throw new Error('A retry resend answers a retry request of its retry ID');
  }
  return member.attempt;
}

/** A resend or a null message that answers a retry request of the local device. */
export interface ResolvedRetryFamilyMember {
  /** The retry ID of the request record. */
  retryId: string;
  /** The ID of the failed envelope that the request record names. */
  failedEnvelopeId: string;
  /** The content resend or the null message. */
  kind: 'resend' | 'null';
  /** The attempt number of the member ID, from 1. */
  attempt: number;
}

/**
 * Get the failed envelope ID that the family index gives for one retry ID.
 * A record older than `RETRY_REQUESTER_RECORD_TTL_MS` does not count.
 */
export async function getRetryFamily(
  store: ReliabilityMetadataStore,
  retryId: string,
  now = Date.now()
): Promise<string | null> {
  const value = await store.getMetadata(recordKey('retry-family', retryId));
  if (value === null) return null;
  const { failedEnvelopeId, indexedAt } = JSON.parse(value);
  if (!Number.isFinite(indexedAt) || typeof failedEnvelopeId !== 'string') {
    throw new Error('Corrupt retry-family record');
  }
  if (indexedAt < now - RETRY_REQUESTER_RECORD_TTL_MS) return null;
  return failedEnvelopeId;
}

/**
 * Resolve an envelope ID to the request record that it answers. An ID that
 * has the shape of a resend or a null message is a family member only when
 * the family index of the local device holds its retry ID. Any other ID
 * gives undefined, and the envelope is an ordinary envelope.
 *
 * The retry ID does not authenticate a member. The Relay sees it, so the
 * Relay, or a device that works with it, can put it on an envelope from any
 * sender. A resolved member answers its request only when the sender that
 * its decrypt authenticates is the account and the device that the request
 * envelope targets. The receive path binds that sender, and a member from
 * any other sender is an ordinary envelope.
 */
export async function resolveRetryFamilyMember(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  now = Date.now()
): Promise<ResolvedRetryFamilyMember | undefined> {
  const member = retryFamilyMember(envelopeId);
  if (!member || member.kind === 'retry-request') return undefined;
  const failedEnvelopeId = await getRetryFamily(store, member.retryId, now);
  if (failedEnvelopeId === null) return undefined;
  return { retryId: member.retryId, failedEnvelopeId, kind: member.kind, attempt: member.attempt };
}

/**
 * The stored attempt of the retry request for one failed envelope, keyed by
 * the failed envelope ID. A later decrypt failure of that envelope posts
 * this envelope again, so the Relay sees one operation for each attempt. A
 * resend or a null message of the same attempt number that arrives marks
 * the attempt answered. A decrypt failure of a resend or a null message
 * posts the next attempt under the same retry ID when the stored attempt is
 * answered, and posts the stored envelope again when it is not.
 */
export interface StoredRetryRequest {
  /** The ID of the envelope that the local device could not decrypt: the key of the record. */
  failedEnvelopeId: string;
  /** The retry ID of the record. Every attempt of the record uses it. */
  retryId: string;
  /** The number of the stored attempt, from 1. It names the client message ID of its post. */
  attempt: number;
  /** The time of the stored attempt. The record expires from this time. */
  requestedAt: number;
  /** The fingerprint of the failed envelope. */
  fingerprint?: string;
  /**
   * True when a resend or a null message of this attempt number arrived.
   * Each new attempt stores false. The member whose decrypt failure created
   * attempt n is of an earlier attempt number, so its redelivery does not
   * answer attempt n, and its post is a replay.
   */
  answered: boolean;
  /**
   * True when the failed envelope is a sender-key group message. A resend
   * that brings only the sender key then does not give the content of the
   * failed envelope.
   */
  groupMessage?: boolean;
  /**
   * The client message ID of the failed envelope, when its relay delivered
   * one. Every attempt of the record carries it.
   */
  failedClientMessageId?: string;
  /**
   * The raw group ID of the failed envelope, when the local device knows it
   * from the sender key that the message names, from the receive that
   * resolved its group, or from the decrypt that gave its content. A
   * pairwise failure has none. Each later attempt keeps it.
   */
  groupId?: string;
  /**
   * The time when the local device first failed to decrypt the failed
   * envelope. Each later attempt keeps it. The delivery error of the record
   * counts from it.
   */
  receivedAt?: number;
  /**
   * The content hint of the failed envelope, when it named one. It sets
   * when the client reports the delivery error. Each later attempt keeps it.
   */
  contentHint?: ContentHint;
  /** The device that sent the failed envelope. Each later attempt keeps it. */
  failedSender?: { userId: string; deviceId: number };
  /**
   * True after the `onDeliveryError` hook returned for the failed envelope.
   * Each later attempt keeps it, so the hook runs again only when it did not
   * return.
   */
  errorShown?: boolean;
  /**
   * True after the `onDeliveryRecovered` hook returned for the failed
   * envelope. Each later attempt keeps it, so the hook runs again only when
   * it did not return.
   */
  recoveredEmitted?: boolean;
  /**
   * The end of the attempts: the time of attempt 1, which is the first
   * failure, plus `RETRY_REQUEST_DEADLINE_MS`. The failed message timestamp
   * does not change it, and each later attempt keeps it. A request whose
   * content did not come at this time ends as `expired-content`, also when
   * its stored attempt is answered.
   */
  deadlineAt: number;
  /**
   * The end of the posts: the first failure, `receivedAt`, plus
   * `RETRY_REQUEST_POSTING_WINDOW_MS`. Each later attempt keeps it. No post
   * starts at or after it. A request whose stored attempt is due at this
   * time ends as `posting-deadline`. A request whose attempt the Relay
   * accepted posts nothing more and waits for its deadline. A record that
   * an earlier SDK stored has none, and `retryRequestPostingDeadlineAt`
   * derives it.
   */
  postingDeadlineAt?: number;
  /**
   * The earliest time of the next post of the stored attempt. A new attempt
   * stores its own time, so an attempt whose post a stop or a crash ended
   * stays due. A post that failed with a retryable class sets a later time.
   * A post that the Relay accepts, and a terminal state, clear it. With no
   * value, the Relay holds the attempt, and the record waits for its answer
   * or its deadline.
   */
  nextAttemptAt?: number;
  /** The class of the last post that failed, until a post succeeds. */
  lastFailureClass?: RetryFailureClass;
  /** The conclusive end of the request. No attempt posts after it. */
  terminal?: RetryTerminal;
  /**
   * The request envelope of the stored attempt. Only a request that ended
   * before its first post, as at an exhausted abuse allowance, has none.
   */
  envelope?: Envelope;
  /**
   * The session reset of an `expired-content` or `posting-deadline` end.
   * Each step is stored when it ends, so a replay does not do a step again.
   * Only a record whose terminal class is `expired-content` or
   * `posting-deadline` has it.
   */
  recovery?: RetryTerminalRecovery;
}

/**
 * The posting deadline of a retry request: the stored `postingDeadlineAt`.
 * A record that an earlier SDK stored has none. Its deadline is then the
 * first failure, `receivedAt`, else the time of the stored attempt, plus
 * `RETRY_REQUEST_POSTING_WINDOW_MS`, and at most `deadlineAt`. An earlier
 * SDK can store a `deadlineAt` one day after the first failure, so
 * `deadlineAt` does not give the time of the first failure.
 */
export function retryRequestPostingDeadlineAt(
  record: Pick<StoredRetryRequest, 'deadlineAt' | 'postingDeadlineAt' | 'receivedAt' | 'requestedAt'>
): number {
  if (record.postingDeadlineAt !== undefined) return record.postingDeadlineAt;
  const firstFailureAt = record.receivedAt ?? record.requestedAt;
  return Math.min(record.deadlineAt, firstFailureAt + RETRY_REQUEST_POSTING_WINDOW_MS);
}

/**
 * The conclusive end of a retry request or a retry resend.
 *
 * - `missing-sender`: the device that sent the failed message is gone, or
 *   it still refuses the request after a refresh of the session with it.
 * - `missing-prekey`: the Relay has no prekey bundle of the requester, so the
 *   sender of the resend cannot start a new session.
 * - `revoked-authority`: the Relay revoked the authority of the post.
 * - `expired-content`: the content of the request did not come before its
 *   deadline. The next major SDK version renames this class to
 *   `request-expired`.
 * - `posting-deadline`: a post of the request was due at or after its
 *   posting deadline, or the Relay refused a post with OPERATION_EXPIRED;
 *   the session resets.
 * - `attempts-exhausted`: the resend that answered the fifth attempt of the
 *   request, `MAX_RETRY_RESPONSES_PER_MESSAGE`, also failed. The sender
 *   answers no later attempt.
 * - `deletion`: the account of the other device is deleted.
 * - `abuse-allowance-exhausted`: the sender used up its retry allowance.
 * - `membership-refused`: the requester is not a current member of the group
 *   of the content, or the sender has no source of current group membership.
 *   The sender sends no content. Only the answer of a sender ends with it.
 */
export type RetryTerminalClass =
  | 'missing-sender'
  | 'missing-prekey'
  | 'revoked-authority'
  | 'expired-content'
  | 'posting-deadline'
  | 'attempts-exhausted'
  | 'deletion'
  | 'abuse-allowance-exhausted'
  | 'membership-refused';

/**
 * The class of a retry request post that failed and can succeed later.
 * `transport-outage`: the post did not reach the Relay, its answer is
 * unknown, or the Relay marked its refusal `retryable`. `rate-refusal`: a
 * rate limit or a full mailbox refused it.
 */
export type RetryFailureClass = 'transport-outage' | 'rate-refusal';

/** The terminal state of a retry record. */
export interface RetryTerminal {
  class: RetryTerminalClass;
  /** The time of the end. */
  at: number;
  /** True after the `onRetryTerminal` hook returned for this end. */
  emitted: boolean;
}

/**
 * The session reset that the requester did after a request ended as
 * `expired-content` or `posting-deadline`.
 */
export interface RetryTerminalRecovery {
  /** The user of the device that sent the failed envelope. */
  userId: string;
  /** The device whose session the requester archived. */
  deviceId: number;
  /**
   * `applied`: the failed envelope has a known group, and the requester has
   * a sender key for it. `skipped`: the failed envelope has no known group,
   * or the requester has no sender key for it. With each outcome, the reset
   * deletes the handoff rows of each device of the account in every group.
   */
  senderKey: 'applied' | 'skipped';
  /** The null message to the device. It is absent until that step ends. */
  nullMessage?: RetryTerminalNullMessage;
}

/**
 * The null message of a session reset. `sent`: the Relay accepted it.
 * `limited`: the requester sent one to the device less than
 * `RETRY_TERMINAL_NULL_MESSAGE_INTERVAL_MS` before. `failed`: its send
 * failed, and the next ordinary message starts the new session.
 */
export interface RetryTerminalNullMessage {
  outcome: 'sent' | 'limited' | 'failed';
  /** The time of the outcome. */
  at: number;
}

/** The shortest time between two session reset null messages to one device. */
export const RETRY_TERMINAL_NULL_MESSAGE_INTERVAL_MS = 60 * 60 * 1_000;

const RETRY_TERMINAL_CLASSES: ReadonlySet<string> = new Set<RetryTerminalClass>([
  'missing-sender',
  'missing-prekey',
  'revoked-authority',
  'expired-content',
  'posting-deadline',
  'attempts-exhausted',
  'deletion',
  'abuse-allowance-exhausted',
  'membership-refused',
]);

function isRetryTerminal(value: unknown): value is RetryTerminal {
  if (value === null || typeof value !== 'object') return false;
  const terminal = value as Partial<RetryTerminal>;
  return (
    typeof terminal.class === 'string' &&
    RETRY_TERMINAL_CLASSES.has(terminal.class) &&
    Number.isFinite(terminal.at) &&
    typeof terminal.emitted === 'boolean'
  );
}

function isRetryTerminalRecovery(value: unknown): value is RetryTerminalRecovery {
  if (value === null || typeof value !== 'object') return false;
  const recovery = value as Partial<RetryTerminalRecovery>;
  const nullMessage = recovery.nullMessage as Partial<RetryTerminalNullMessage> | undefined;
  return (
    typeof recovery.userId === 'string' &&
    Number.isSafeInteger(recovery.deviceId) &&
    (recovery.senderKey === 'applied' || recovery.senderKey === 'skipped') &&
    (nullMessage === undefined ||
      (typeof nullMessage === 'object' &&
        nullMessage !== null &&
        (nullMessage.outcome === 'sent' ||
          nullMessage.outcome === 'limited' ||
          nullMessage.outcome === 'failed') &&
        Number.isFinite(nullMessage.at)))
  );
}

/**
 * Get the stored retry request for one failed envelope. A record older than
 * `RETRY_REQUESTER_RECORD_TTL_MS` does not count.
 *
 * @throws RetryRequestedEnvelopeChangedError When the stored fingerprint is
 *   not the given fingerprint.
 */
export async function getRetryRequest(
  store: ReliabilityMetadataStore,
  failedEnvelopeId: string,
  now = Date.now(),
  fingerprint?: string
): Promise<StoredRetryRequest | null> {
  const record = parseJson<StoredRetryRequest | null>(
    await store.getMetadata(recordKey('retry-requested', failedEnvelopeId)),
    null
  );
  if (!record) return null;
  if (
    !Number.isFinite(record.requestedAt) ||
    record.failedEnvelopeId !== failedEnvelopeId ||
    !isRetryId(record.retryId) ||
    !Number.isSafeInteger(record.attempt) ||
    record.attempt < 1 ||
    typeof record.answered !== 'boolean' ||
    !Number.isFinite(record.deadlineAt) ||
    (record.postingDeadlineAt !== undefined && !Number.isFinite(record.postingDeadlineAt)) ||
    (record.nextAttemptAt !== undefined && !Number.isFinite(record.nextAttemptAt)) ||
    (record.lastFailureClass !== undefined &&
      record.lastFailureClass !== 'transport-outage' &&
      record.lastFailureClass !== 'rate-refusal') ||
    (record.terminal !== undefined && !isRetryTerminal(record.terminal)) ||
    (record.envelope === undefined && record.terminal === undefined) ||
    (record.receivedAt !== undefined && !Number.isFinite(record.receivedAt)) ||
    (record.errorShown !== undefined && typeof record.errorShown !== 'boolean') ||
    (record.recoveredEmitted !== undefined && typeof record.recoveredEmitted !== 'boolean') ||
    (record.groupId !== undefined && (typeof record.groupId !== 'string' || !record.groupId)) ||
    (record.failedSender !== undefined &&
      (typeof record.failedSender?.userId !== 'string' ||
        !Number.isSafeInteger(record.failedSender.deviceId))) ||
    (record.recovery !== undefined &&
      ((record.terminal?.class !== 'expired-content' &&
        record.terminal?.class !== 'posting-deadline') ||
        !isRetryTerminalRecovery(record.recovery)))
  ) {
    throw new Error('Corrupt retry-request record');
  }
  if (record.requestedAt < now - RETRY_REQUESTER_RECORD_TTL_MS) return null;
  if (fingerprint !== undefined && fingerprint !== record.fingerprint) {
    throw new RetryRequestedEnvelopeChangedError();
  }
  return cloneReliabilityValue(record);
}

/**
 * Mark the stored attempt of a retry request answered when a resend or a
 * null message of its retry ID and its attempt number arrives. A member of
 * another attempt number answers nothing. An expired record, a record of
 * another retry ID and an answered attempt stay as they are.
 *
 * @param store - The local store that keeps the request records.
 * @param failedEnvelopeId - The failed envelope of the family.
 * @param retryId - The retry ID of the arriving envelope.
 * @param attempt - The attempt number of the arriving envelope ID.
 * @param now - The current time.
 */
export async function markRetryRequestAnswered(
  store: ReliabilityMetadataStore,
  failedEnvelopeId: string,
  retryId: string,
  attempt: number,
  now = Date.now()
): Promise<void> {
  await serializeMutation(store, async () => {
    const record = await getRetryRequest(store, failedEnvelopeId, now);
    if (
      !record ||
      record.retryId !== retryId ||
      record.answered ||
      record.attempt !== attempt
    ) {
      return;
    }
    // The attempt keeps its time, so its bucket index stays. An answer ends
    // the wait for a later post of the attempt.
    await store.setMetadata(
      recordKey('retry-requested', failedEnvelopeId),
      JSON.stringify({
        ...record,
        answered: true,
        nextAttemptAt: undefined,
        lastFailureClass: undefined,
      })
    );
  });
}

/**
 * Change the lifecycle fields of the stored attempt of a retry request. It
 * writes only when the record holds the given retry ID and attempt, so a
 * change for an attempt that a later attempt replaced writes nothing. A
 * field with the value undefined is removed. The attempt keeps its time,
 * so its bucket index stays.
 *
 * @returns The changed record, or null when no record matched.
 */
export async function updateRetryRequest(
  store: ReliabilityMetadataStore,
  failedEnvelopeId: string,
  retryId: string,
  attempt: number,
  changes: Partial<
    Pick<
      StoredRetryRequest,
      | 'nextAttemptAt'
      | 'lastFailureClass'
      | 'terminal'
      | 'errorShown'
      | 'recoveredEmitted'
      | 'groupId'
      | 'recovery'
    >
  >,
  now = Date.now()
): Promise<StoredRetryRequest | null> {
  return serializeMutation(store, async () => {
    const record = await getRetryRequest(store, failedEnvelopeId, now);
    if (!record || record.retryId !== retryId || record.attempt !== attempt) return null;
    const changed = cloneReliabilityValue({ ...record, ...changes });
    await store.setMetadata(
      recordKey('retry-requested', failedEnvelopeId),
      JSON.stringify(changed)
    );
    return changed;
  });
}

/**
 * The failed envelope IDs of the stored retry requests that are not older
 * than `RETRY_REQUESTER_RECORD_TTL_MS`. The caller reads each record with
 * `getRetryRequest`.
 */
export async function listRetryRequestIds(
  store: ReliabilityMetadataStore,
  now = Date.now()
): Promise<string[]> {
  const firstRetainedDay = dayFor(now - RETRY_REQUESTER_RECORD_TTL_MS);
  const days = parseJson<number[]>(await store.getMetadata(manifestKey('retry-requested')), []);
  const ids: string[] = [];
  for (const day of days) {
    if (day < firstRetainedDay) continue;
    for (const id of parseJson<string[]>(
      await store.getMetadata(bucketKey('retry-requested', day)),
      []
    )) {
      if (!ids.includes(id)) ids.push(id);
    }
  }
  return ids;
}

/** The key prefix of the retry request records before the lifecycle fields. */
const RETRY_REQUESTED_V1_PREFIX = 'reliability:retry-requested:v1';

/** A v1 retry request record, or null for a value that does not parse. */
function parseV1RetryRequest(value: string | null): Omit<StoredRetryRequest, 'deadlineAt'> | null {
  try {
    const record = parseJson<Omit<StoredRetryRequest, 'deadlineAt'> | null>(value, null);
    return record !== null && typeof record === 'object' ? record : null;
  } catch {
    return null;
  }
}

/**
 * Move each retry request record of the v1 prefix to the current prefix,
 * and delete the v1 keys. A v1 record has no deadline, so the moved record
 * gets the time of its stored attempt plus `RETRY_REQUEST_DEADLINE_MS`. A
 * v1 record does not tell whether the post of its attempt reached the
 * Relay, so an unanswered record is due at the time of its stored attempt,
 * and the scheduler posts its stored bytes again. A
 * record older than `RETRY_REQUESTER_RECORD_TTL_MS`, and a record that does
 * not parse, is deleted. With no v1 keys, it writes nothing.
 */
export async function migrateRetryRequestRecords(
  store: ReliabilityMetadataStore,
  now = Date.now()
): Promise<void> {
  const v1ManifestKey = `${RETRY_REQUESTED_V1_PREFIX}:manifest`;
  const days = parseJson<number[]>(await store.getMetadata(v1ManifestKey), []);
  if (days.length === 0) return;
  await serializeMutation(store, async () => {
    for (const day of days) {
      const v1BucketKey = `${RETRY_REQUESTED_V1_PREFIX}:bucket:${day}`;
      for (const id of parseJson<string[]>(await store.getMetadata(v1BucketKey), [])) {
        const v1RecordKey = `${RETRY_REQUESTED_V1_PREFIX}:record:${encodeURIComponent(id)}`;
        const record = parseV1RetryRequest(await store.getMetadata(v1RecordKey));
        if (
          record &&
          Number.isFinite(record.requestedAt) &&
          record.requestedAt >= now - RETRY_REQUESTER_RECORD_TTL_MS
        ) {
          const retainedDays = await pruneExpiredBuckets(store, 'retry-requested', now);
          await store.setMetadata(
            recordKey('retry-requested', id),
            JSON.stringify({
              ...record,
              deadlineAt: record.requestedAt + RETRY_REQUEST_DEADLINE_MS,
              ...(!record.answered &&
                record.envelope !== undefined && { nextAttemptAt: record.requestedAt }),
            })
          );
          await indexRecord(store, 'retry-requested', id, record.requestedAt, retainedDays);
        }
        await store.deleteMetadata(v1RecordKey);
      }
      await store.deleteMetadata(v1BucketKey);
    }
    await store.deleteMetadata(v1ManifestKey);
  });
}

/**
 * Record the request envelope of a retry request before its post, and the
 * family index entry from its retry ID to the failed envelope ID. One
 * mutation writes both. The two writes are serialized, not atomic, and the
 * index write comes first. Only a failure between the two writes leaves an
 * index entry with no request record, so the case is practically
 * unreachable. A member of that retry ID then still resolves to the
 * failed envelope. Its decrypt stores the failed envelope processed, and
 * its decrypt failure creates attempt 1 under a new retry ID. A record
 * that a member creates has no fingerprint, so a later failure of the
 * failed envelope with a fingerprint reads as a changed envelope and posts
 * nothing. A later attempt replaces the earlier one in one write, so the
 * record holds an attempt at each point.
 */
export async function storeRetryRequest(
  store: ReliabilityMetadataStore,
  request: StoredRetryRequest
): Promise<void> {
  await serializeMutation(store, async () => {
    // A request with no envelope posted nothing, so no member can name it.
    if (request.envelope) await indexRetryFamily(store, request);
    const key = recordKey('retry-requested', request.failedEnvelopeId);
    const replaced = parseJson<StoredRetryRequest | null>(await store.getMetadata(key), null);
    const retainedDays = await pruneExpiredBuckets(store, 'retry-requested', request.requestedAt);
    await store.setMetadata(key, JSON.stringify(request));
    await indexRecord(
      store,
      'retry-requested',
      request.failedEnvelopeId,
      request.requestedAt,
      retainedDays
    );
    // The bucket of the replaced attempt would prune the new attempt early.
    if (replaced && dayFor(replaced.requestedAt) !== dayFor(request.requestedAt)) {
      await unindexRecord(store, 'retry-requested', request.failedEnvelopeId, replaced.requestedAt);
    }
  });
}

/**
 * Write the family index entry of a request attempt. Each attempt writes it
 * again with its own time, so the entry lives as long as the request record.
 */
async function indexRetryFamily(
  store: ReliabilityMetadataStore,
  request: StoredRetryRequest
): Promise<void> {
  const key = recordKey('retry-family', request.retryId);
  const replaced = parseJson<{ indexedAt: number } | null>(await store.getMetadata(key), null);
  const retainedDays = await pruneExpiredBuckets(store, 'retry-family', request.requestedAt);
  await store.setMetadata(
    key,
    JSON.stringify({ failedEnvelopeId: request.failedEnvelopeId, indexedAt: request.requestedAt })
  );
  await indexRecord(store, 'retry-family', request.retryId, request.requestedAt, retainedDays);
  if (replaced && dayFor(replaced.indexedAt) !== dayFor(request.requestedAt)) {
    await unindexRecord(store, 'retry-family', request.retryId, replaced.indexedAt);
  }
}

/**
 * The retry request that a resend or a null message answers. The sender
 * takes it from the request envelope and its payload.
 */
export interface RetryResendTarget {
  /** The retry ID of the requester's record. The answer IDs derive from it. */
  retryId: string;
  /** The ID of the request attempt that the answer goes to. */
  requestEnvelopeId: string;
  /** The ID of the envelope that the requester could not decrypt. */
  failedEnvelopeId: string;
  /** A resend of the content, or the null message of a session reset. */
  kind: 'resend' | 'null';
}

/**
 * The stored answer to the retry requests for one failed envelope. The
 * record key is the device that gets the answer and the failed envelope
 * ID. The record holds the last encryption: a later post for the same
 * request attempt and kind sends these bytes with this operation epoch
 * again, so the Relay sees one operation. The record also holds the
 * acceptance-unknown mark of that attempt, after which nothing more posts
 * under its ID.
 */
export interface StoredRetryResend extends RetryResendTarget {
  /**
   * The attempt number of the request that the answer goes to, from
   * `retryRequestAttempt`. With the retry ID and the kind, it names the
   * client message ID of the post.
   */
  attempt: number;
  /** The operation epoch of the stored bytes. The record expires from this time. */
  operationEpochMilliseconds: number;
  transportMode: StoredOutgoingMessageIntent['transportMode'];
  /**
   * The sealed authorization of the post. A group endorsement is stored by
   * its group, and the endorsement of the device's account resolves again
   * at each post.
   */
  sealedSenderAuth?:
    | { type: 'accessKey'; unidentifiedAccessKey: string }
    | { type: 'groupSendToken'; groupId: string };
  contentHint?: ContentHint;
  message: StoredOutgoingDeviceMessage;
  /**
   * Set when the Relay refused the stored bytes with OPERATION_EXPIRED. The
   * Relay acceptance of the attempt is unknown, so nothing more posts under
   * its ID, and no new encryption replaces it. A record without the field
   * is not marked.
   */
  acceptanceUnknown?: true;
  /** A stored encryption has no terminal state. */
  terminal?: undefined;
}

/**
 * The conclusive end of the answer to one device for one failed envelope,
 * in place of an encryption. The sender answers no later request for that
 * envelope from that device. The record expires from the time of the end.
 */
export interface RetryResendTerminal extends RetryResendTarget {
  /** The attempt number of the request that ended the answer. */
  attempt: number;
  /** The user that asked for the answer. */
  recipientUserId: string;
  /** The device that asked for the answer. */
  recipientDeviceId: number;
  terminal: RetryTerminal;
}

/**
 * A direct send gives each device of the recipient the same message ID, so
 * one failed envelope ID can come from more than one device.
 */
function retryResendRecordId(
  recipientUserId: string,
  recipientDeviceId: number,
  failedEnvelopeId: string
): string {
  return JSON.stringify([recipientUserId, recipientDeviceId, failedEnvelopeId]);
}

/**
 * Get the stored answer to one device for one failed envelope. A record
 * older than `RELIABILITY_RECORD_TTL_MS` does not count.
 */
export async function getRetryResend(
  store: ReliabilityMetadataStore,
  recipientUserId: string,
  recipientDeviceId: number,
  failedEnvelopeId: string,
  now = Date.now()
): Promise<StoredRetryResend | RetryResendTerminal | null> {
  const record = parseJson<StoredRetryResend | RetryResendTerminal | null>(
    await store.getMetadata(
      recordKey(
        'retry-resend',
        retryResendRecordId(recipientUserId, recipientDeviceId, failedEnvelopeId)
      )
    ),
    null
  );
  if (!record) return null;
  if (record.terminal !== undefined) {
    if (
      !isRetryTerminal(record.terminal) ||
      record.failedEnvelopeId !== failedEnvelopeId ||
      !isRetryId(record.retryId) ||
      typeof record.requestEnvelopeId !== 'string' ||
      (record.kind !== 'resend' && record.kind !== 'null') ||
      record.recipientUserId !== recipientUserId ||
      record.recipientDeviceId !== recipientDeviceId ||
      !answersItsRequestAttempt(record)
    ) {
      throw new Error('Corrupt retry-resend record');
    }
    if (record.terminal.at < now - RELIABILITY_RECORD_TTL_MS) return null;
    return cloneReliabilityValue(record);
  }
  if (
    !Number.isFinite(record.operationEpochMilliseconds) ||
    record.failedEnvelopeId !== failedEnvelopeId ||
    !isRetryId(record.retryId) ||
    typeof record.requestEnvelopeId !== 'string' ||
    (record.kind !== 'resend' && record.kind !== 'null') ||
    record.message?.recipientUserId !== recipientUserId ||
    record.message.recipientDeviceId !== recipientDeviceId ||
    !answersItsRequestAttempt(record)
  ) {
    throw new Error('Corrupt retry-resend record');
  }
  if (record.operationEpochMilliseconds < now - RELIABILITY_RECORD_TTL_MS) return null;
  return cloneReliabilityValue(record);
}

/** True when the record carries the attempt number of its request. */
function answersItsRequestAttempt(record: StoredRetryResend | RetryResendTerminal): boolean {
  const member = retryFamilyMember(record.requestEnvelopeId);
  return (
    member?.kind === 'retry-request' &&
    member.retryId === record.retryId &&
    member.attempt === record.attempt
  );
}

/** The time from which a retry-resend record expires. */
function retryResendTime(record: StoredRetryResend | RetryResendTerminal): number {
  return record.terminal === undefined ? record.operationEpochMilliseconds : record.terminal.at;
}

/**
 * Record the encrypted bytes of a retry resend before their post, or the
 * terminal state of the answer. A later write replaces the earlier one in
 * one write, so the record holds one state at each point. Throws, and
 * writes nothing, when the attempt is not the attempt number of the
 * request envelope.
 */
export async function storeRetryResend(
  store: ReliabilityMetadataStore,
  resend: StoredRetryResend | RetryResendTerminal
): Promise<void> {
  if (resend.attempt !== retryRequestAttempt(resend)) {
    throw new Error('A retry resend carries the attempt number of its request');
  }
  await serializeMutation(store, async () => {
    const id =
      resend.terminal === undefined
        ? retryResendRecordId(
            resend.message.recipientUserId,
            resend.message.recipientDeviceId,
            resend.failedEnvelopeId
          )
        : retryResendRecordId(
            resend.recipientUserId,
            resend.recipientDeviceId,
            resend.failedEnvelopeId
          );
    const key = recordKey('retry-resend', id);
    const replaced = parseJson<StoredRetryResend | RetryResendTerminal | null>(
      await store.getMetadata(key),
      null
    );
    const time = retryResendTime(resend);
    const retainedDays = await pruneExpiredBuckets(store, 'retry-resend', time);
    await store.setMetadata(key, JSON.stringify(resend));
    await indexRecord(store, 'retry-resend', id, time, retainedDays);
    // The bucket of the replaced time would prune the new record early.
    if (replaced && dayFor(retryResendTime(replaced)) !== dayFor(time)) {
      await unindexRecord(store, 'retry-resend', id, retryResendTime(replaced));
    }
  });
}
