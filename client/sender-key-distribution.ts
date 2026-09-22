import { base64ToBytes, bytesToBase64 } from '../internal/crypto';
import type { SenderKeyDistributionMessage } from '../internal/protocol/sender-keys';
import type { Base64 } from '../types';

export interface ParsedSenderKeyDistribution {
  groupId: string;
  distribution: SenderKeyDistributionMessage;
}

function invalidDistribution(): never {
  throw new Error('Invalid encrypted sender-key distribution');
}

function uint32(value: unknown): value is number {
  return (
    Number.isInteger(value) &&
    Number(value) >= 0 &&
    Number(value) <= 0xffff_ffff
  );
}

function key(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const bytes = base64ToBytes(value as Base64);
    return bytes.length === 32 && bytesToBase64(bytes) === value;
  } catch {
    return false;
  }
}

/** Validate decrypted content before it can change sender-key state. */
export function parseSenderKeyDistribution(
  value: unknown,
): ParsedSenderKeyDistribution {
  if (typeof value !== 'string') return invalidDistribution();
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return invalidDistribution();
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return invalidDistribution();
  }
  const item = parsed as Record<string, unknown>;
  if (
    typeof item.groupId !== 'string' ||
    item.groupId.length === 0 ||
    typeof item.senderKeyId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      item.senderKeyId,
    ) ||
    !uint32(item.chainId) ||
    !uint32(item.chainIndex) ||
    !Number.isSafeInteger(item.generation) ||
    Number(item.generation) < 1 ||
    !key(item.chainKey) ||
    !key(item.publicSignatureKey)
  )
    return invalidDistribution();
  return {
    groupId: item.groupId,
    distribution: {
      senderKeyId: item.senderKeyId,
      chainId: item.chainId,
      chainIndex: item.chainIndex,
      generation: Number(item.generation),
      chainKey: item.chainKey,
      publicSignatureKey: item.publicSignatureKey,
    },
  };
}
