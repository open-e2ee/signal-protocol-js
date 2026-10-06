import type { SignalProtocolLocalStore } from '../../types';
import type { ContentHint } from '../../types/messages';
import { createKeyedLocks, withKeyedLock } from '../../utils/keyed-lock';

const OUTBOX_PREFIX = 'reliability:exact-ciphertext-outbox:v2';
const INCOMING_PREFIX = 'reliability:processed-envelopes:v2';
const DAY_MS = 24 * 60 * 60 * 1_000;

export const RELIABILITY_RECORD_TTL_MS = 30 * DAY_MS;

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
type LedgerKind = 'outbox' | 'incoming';

const mutationTails = new WeakMap<object, Promise<void>>();
const outgoingIntentLocks = createKeyedLocks();
const incomingEnvelopeLocks = createKeyedLocks();

function prefix(kind: LedgerKind): string {
  return kind === 'outbox' ? OUTBOX_PREFIX : INCOMING_PREFIX;
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
  const firstRetainedDay = dayFor(now - RELIABILITY_RECORD_TTL_MS);
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
    if (!retainedExisting) await store.setMetadata(key, JSON.stringify(intent));
    await indexRecord(store, 'outbox', intent.clientMessageId, intent.createdAt, retainedDays);
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

export async function hasProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  now = Date.now(),
  fingerprint?: string
): Promise<boolean> {
  const value = await store.getMetadata(recordKey('incoming', envelopeId));
  if (value === null) return false;
  const { processedAt, fingerprint: storedFingerprint } = JSON.parse(value);
  if (!Number.isFinite(processedAt)) throw new Error('Corrupt processed-envelope record');
  if (fingerprint !== undefined && fingerprint !== storedFingerprint) {
    throw new Error('Relay envelope identity changed after processing');
  }
  return processedAt >= now - RELIABILITY_RECORD_TTL_MS;
}

export async function storeProcessedEnvelope(
  store: ReliabilityMetadataStore,
  envelopeId: string,
  processedAt = Date.now(),
  fingerprint?: string
): Promise<void> {
  await serializeMutation(store, async () => {
    const retainedDays = await pruneExpiredBuckets(store, 'incoming', processedAt);
    await store.setMetadata(
      recordKey('incoming', envelopeId),
      JSON.stringify({ processedAt, fingerprint })
    );
    await indexRecord(store, 'incoming', envelopeId, processedAt, retainedDays);
  });
}
