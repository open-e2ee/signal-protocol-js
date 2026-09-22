import { sha256, bytesToBase64 } from '../../internal/crypto';
import type { Envelope } from '../../remote/relay/types';
import type { ISignalProtocolLocalStore, ReceivedContent } from '../../types/api';
import { RELIABILITY_RECORD_TTL_MS } from './reliability';

/** Bind recovery to the exact envelope and the device that consumed it. */
export async function receivedContentId(
  userId: string,
  deviceId: number,
  envelope: Envelope
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
        envelope.timestamp ?? null,
        envelope.serverTimestamp ?? null,
        ciphertext,
      ])
    )
  );
  return bytesToBase64(digest);
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
export async function pruneReceivedContent(store: ISignalProtocolLocalStore): Promise<void> {
  const now = Date.now();
  const last = lastCleanup.get(store);
  if (last !== undefined && now >= last && now - last < 60_000) return;
  await store.deleteExpiredReceivedContent(now - RELIABILITY_RECORD_TTL_MS);
  lastCleanup.set(store, now);
}
