import type { Envelope } from '../../remote/relay/types';
import type { SignalProtocolLocalStore } from '../../types';
import type { ContentHint } from '../../types/messages';
import { createKeyedLocks, withKeyedLock } from '../../utils/keyed-lock';

const OUTBOX_PREFIX = 'reliability:exact-ciphertext-outbox:v2';
const INCOMING_PREFIX = 'reliability:processed-envelopes:v2';
const RETRY_REQUESTED_PREFIX = 'reliability:retry-requested:v1';
const RETRY_RESEND_PREFIX = 'reliability:retry-resend:v1';
const RETRY_FAMILY_PREFIX = 'reliability:retry-family:v1';
const SENT_TIMESTAMP_PREFIX = 'reliability:sent-timestamps:v1';
const DELIVERY_STATUS_PREFIX = 'reliability:delivery-status:v1';
const DAY_MS = 24 * 60 * 60 * 1_000;

export const RELIABILITY_RECORD_TTL_MS = 30 * DAY_MS;

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
  result?: {
    clientMessageId: string;
    messageId: string;
    timestamp: number;
    recipientDeviceCount: number;
    duplicate?: boolean;
    expiresAt?: number;
    groupId?: string;
  };
}

type ReliabilityMetadataStore = Pick<
  SignalProtocolLocalStore,
  'getMetadata' | 'setMetadata' | 'deleteMetadata'
>;
type LedgerKind =
  | 'outbox'
  | 'incoming'
  | 'retry-requested'
  | 'retry-family'
  | 'retry-resend'
  | 'sent-timestamp'
  | 'delivery-status';

const mutationTails = new WeakMap<object, Promise<void>>();
const outgoingIntentLocks = createKeyedLocks();
const incomingEnvelopeLocks = createKeyedLocks();

const LEDGER_PREFIXES: Record<LedgerKind, string> = {
  outbox: OUTBOX_PREFIX,
  incoming: INCOMING_PREFIX,
  'retry-requested': RETRY_REQUESTED_PREFIX,
  'retry-family': RETRY_FAMILY_PREFIX,
  'retry-resend': RETRY_RESEND_PREFIX,
  'sent-timestamp': SENT_TIMESTAMP_PREFIX,
  'delivery-status': DELIVERY_STATUS_PREFIX,
};

const LEDGER_TTL_MS: Record<LedgerKind, number> = {
  outbox: RELIABILITY_RECORD_TTL_MS,
  incoming: RELIABILITY_RECORD_TTL_MS,
  'retry-requested': RETRY_REQUESTER_RECORD_TTL_MS,
  'retry-family': RETRY_REQUESTER_RECORD_TTL_MS,
  'retry-resend': RELIABILITY_RECORD_TTL_MS,
  'sent-timestamp': RELIABILITY_RECORD_TTL_MS,
  'delivery-status': RELIABILITY_RECORD_TTL_MS,
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

export async function withOutgoingMessageIntentLock<T>(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  operation: () => Promise<T>
): Promise<T> {
  return withKeyedLock(outgoingIntentLocks, store, clientMessageId, operation);
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
  const retained: number[] = [];
  for (const day of days) {
    if (day >= firstRetainedDay) {
      retained.push(day);
      continue;
    }
    const ids = parseJson<string[]>(await store.getMetadata(bucketKey(kind, day)), []);
    for (const id of ids) await store.deleteMetadata(recordKey(kind, id));
    await store.deleteMetadata(bucketKey(kind, day));
  }
  return retained;
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

export async function appendOutgoingGroupDeviceMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  messages: StoredOutgoingDeviceMessage[]
): Promise<StoredOutgoingMessageIntent> {
  return serializeMutation(store, async () => {
    const key = recordKey('outbox', clientMessageId);
    const existing = parseJson<StoredOutgoingMessageIntent | null>(
      await store.getMetadata(key),
      null
    );
    if (!existing || existing.kind !== 'group' || existing.result) {
      throw new Error('Cannot extend a missing or completed group outbox intent');
    }

    for (const message of messages) {
      const prior = existing.deviceMessages.find(
        (candidate) =>
          candidate.recipientUserId === message.recipientUserId &&
          candidate.recipientDeviceId === message.recipientDeviceId
      );
      if (prior) {
        if (JSON.stringify(prior) !== JSON.stringify(message)) {
          throw new Error('Cannot replace a persisted group repair transmission');
        }
        continue;
      }
      existing.deviceMessages.push(cloneReliabilityValue(message));
    }

    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

/**
 * Remove the pre-messages that the relay accepted from a group intent, so a
 * replay posts only the pre-messages that the relay did not accept.
 */
export async function confirmOutgoingPreMessages(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  acceptedClientMessageIds: readonly string[]
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
    const remaining = (existing.preMessages ?? []).filter(
      (message) => message.clientMessageId === undefined || !accepted.has(message.clientMessageId)
    );
    if (remaining.length > 0) existing.preMessages = remaining;
    else delete existing.preMessages;

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

    await store.setMetadata(key, JSON.stringify(existing));
    return cloneReliabilityValue(existing);
  });
}

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
  if (!record || record.createdAt < now - RELIABILITY_RECORD_TTL_MS) return null;
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
      existing && existing.createdAt >= now - RELIABILITY_RECORD_TTL_MS ? existing : null;
    if (retainedExisting && !sameIntent(retainedExisting, intent)) {
      throw new Error('A clientMessageId cannot identify two different encrypted sends');
    }
    if (!retainedExisting) {
      await store.setMetadata(key, JSON.stringify(intent));
      await indexSentTimestamp(store, intent, now);
    }
    await indexRecord(store, 'outbox', intent.clientMessageId, intent.createdAt, retainedDays);
  });
}

/**
 * Index the client message ID of a new intent under its client timestamp,
 * the value by which an E2EE receipt names the message. The index expires
 * with the intent.
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

export async function completeOutgoingMessageIntent(
  store: ReliabilityMetadataStore,
  clientMessageId: string,
  result: NonNullable<StoredOutgoingMessageIntent['result']>
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
    existing.result = cloneReliabilityValue(result);
    delete existing.reconcilePending;
    delete existing.preMessages;
    existing.deviceMessages = [];
    existing.syncMessages = [];
    delete existing.sealedSenderAuth;
    delete existing.groupCiphertext;
    delete existing.groupSenderKeyDistributionId;
    delete existing.groupSharedMessage;
    await store.setMetadata(key, JSON.stringify(existing));
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
}

/** The lifetime of one processed-envelope record. */
function processedEnvelopeTtl(record: ProcessedEnvelope): number {
  return record.fulfilled ? RETRY_REQUESTER_RECORD_TTL_MS : RELIABILITY_RECORD_TTL_MS;
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
  const { processedAt, fingerprint, fulfilled } = JSON.parse(value);
  if (
    !Number.isFinite(processedAt) ||
    (fingerprint !== undefined && typeof fingerprint !== 'string') ||
    (fulfilled !== undefined && fulfilled !== true)
  ) {
    throw new Error('Corrupt processed-envelope record');
  }
  return {
    processedAt,
    ...(fingerprint !== undefined && { fingerprint }),
    ...(fulfilled === true && { fulfilled }),
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
 * the fingerprint and the fulfilled flag of a record that counts, so a
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
  await serializeMutation(store, async () => {
    const existing = await readProcessedEnvelope(store, envelopeId);
    const current =
      existing && existing.processedAt >= processedAt - processedEnvelopeTtl(existing)
        ? existing
        : null;
    const keptFingerprint = fingerprint ?? current?.fingerprint;
    const record: ProcessedEnvelope = {
      processedAt,
      ...(keptFingerprint !== undefined && { fingerprint: keptFingerprint }),
      ...((fulfilled || current?.fulfilled) && { fulfilled: true as const }),
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
 * answers. A new encryption for the same request attempt posts the same
 * ID, and the processed ledger of the requester and the RETRY_CONFLICT
 * answer of the Relay cover the new bytes.
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
 * The sender of a member is not bound to the target of the request. The
 * retry ID is a random UUID that only the requester, the Relay and the
 * requested sender see, so another sender cannot name it.
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
  /** The request envelope of the stored attempt. */
  envelope: Envelope;
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
    typeof record.answered !== 'boolean'
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
    // The attempt keeps its time, so its bucket index stays.
    await store.setMetadata(
      recordKey('retry-requested', failedEnvelopeId),
      JSON.stringify({ ...record, answered: true })
    );
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
    await indexRetryFamily(store, request);
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
 * again, so the Relay sees one operation.
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
  sealedSenderAuth?: { type: 'accessKey'; unidentifiedAccessKey: string };
  contentHint?: ContentHint;
  message: StoredOutgoingDeviceMessage;
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
): Promise<StoredRetryResend | null> {
  const record = parseJson<StoredRetryResend | null>(
    await store.getMetadata(
      recordKey(
        'retry-resend',
        retryResendRecordId(recipientUserId, recipientDeviceId, failedEnvelopeId)
      )
    ),
    null
  );
  if (!record) return null;
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
function answersItsRequestAttempt(record: StoredRetryResend): boolean {
  const member = retryFamilyMember(record.requestEnvelopeId);
  return (
    member?.kind === 'retry-request' &&
    member.retryId === record.retryId &&
    member.attempt === record.attempt
  );
}

/**
 * Record the encrypted bytes of a retry resend before their post. A later
 * encryption replaces the earlier one in one write, so the record holds an
 * encryption at each point. Throws, and writes nothing, when the attempt
 * is not the attempt number of the request envelope.
 */
export async function storeRetryResend(
  store: ReliabilityMetadataStore,
  resend: StoredRetryResend
): Promise<void> {
  if (resend.attempt !== retryRequestAttempt(resend)) {
    throw new Error('A retry resend carries the attempt number of its request');
  }
  await serializeMutation(store, async () => {
    const id = retryResendRecordId(
      resend.message.recipientUserId,
      resend.message.recipientDeviceId,
      resend.failedEnvelopeId
    );
    const key = recordKey('retry-resend', id);
    const replaced = parseJson<StoredRetryResend | null>(await store.getMetadata(key), null);
    const retainedDays = await pruneExpiredBuckets(
      store,
      'retry-resend',
      resend.operationEpochMilliseconds
    );
    await store.setMetadata(key, JSON.stringify(resend));
    await indexRecord(store, 'retry-resend', id, resend.operationEpochMilliseconds, retainedDays);
    // The bucket of the replaced epoch would prune the new attempt early.
    if (
      replaced &&
      dayFor(replaced.operationEpochMilliseconds) !== dayFor(resend.operationEpochMilliseconds)
    ) {
      await unindexRecord(store, 'retry-resend', id, replaced.operationEpochMilliseconds);
    }
  });
}
