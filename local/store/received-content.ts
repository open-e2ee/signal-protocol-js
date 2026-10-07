import { sha256, bytesToBase64 } from '../../internal/crypto';
import type { Envelope } from '../../remote/relay/types';
import type { SignalProtocolLocalStore, ReceivedContent } from '../../types/api';
import { RELIABILITY_RECORD_TTL_MS } from './reliability';

/**
 * Bind recovery to the device that consumed an envelope, and to the
 * envelope ID, the sender, the message type and the ciphertext of the
 * envelope. The timestamps are not part of the ID: a push can omit the
 * server timestamp that a pull of the same envelope sets.
 */
export async function receivedContentId(
  userId: string,
  deviceId: number,
  envelope: Pick<Envelope, 'senderUserId' | 'senderDeviceId' | 'ciphertext' | 'id'> & {
    messageType?: string;
  }
): Promise<string> {
  const ciphertext =
    typeof envelope.ciphertext === 'string'
      ? envelope.ciphertext
      : bytesToBase64(envelope.ciphertext);
  const digest = await sha256(
    new TextEncoder().encode(
      JSON.stringify([
        userId,
        deviceId,
        envelope.id,
        envelope.senderUserId,
        envelope.senderDeviceId,
        envelope.messageType,
        ciphertext,
      ])
    )
  );
  return bytesToBase64(digest);
}

/**
 * The fingerprint of an envelope as the Relay delivered it. Every receive
 * path gives one value for one delivered envelope: an absent message type
 * is `ciphertext`, as the Relay delivers it, a sealed envelope is hashed
 * before any unseal, and the timestamps are not part of the value.
 */
export async function deliveredEnvelopeFingerprint(
  userId: string,
  deviceId: number,
  envelope: Parameters<typeof receivedContentId>[2]
): Promise<string> {
  return receivedContentId(userId, deviceId, {
    ...envelope,
    messageType: envelope.messageType ?? 'ciphertext',
  });
}

export function receivedContentKey(id: string): string {
  return `received-content:${id}`;
}

export function parseReceivedContent(value: string, id: string): ReceivedContent {
  const record = JSON.parse(value) as ReceivedContent;
  if (
    record.id !== id ||
    typeof record.plaintext !== 'string' ||
    !Number.isSafeInteger(record.receivedAt) ||
    record.receivedAt <= 0 ||
    (record.groupId !== undefined &&
      (typeof record.groupId !== 'string' || record.groupId.length === 0))
  ) {
    throw new Error('Invalid received-content record');
  }
  return record;
}

const lastCleanup = new WeakMap<object, number>();

/** Expired content follows the same thirty-day horizon as incoming retry evidence. */
export async function pruneReceivedContent(store: SignalProtocolLocalStore): Promise<void> {
  const now = Date.now();
  const last = lastCleanup.get(store);
  if (last !== undefined && now >= last && now - last < 60_000) return;
  await store.deleteExpiredReceivedContent(now - RELIABILITY_RECORD_TTL_MS);
  lastCleanup.set(store, now);
}
