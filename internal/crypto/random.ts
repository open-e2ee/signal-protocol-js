import { hostRandomBytes } from '#secure-random-host';

/** Generate secure random bytes from the runtime host. */
export async function generateRandomBytes(size: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('Random byte length must be a nonnegative safe integer.');
  }
  return hostRandomBytes(size);
}

/**
 * Generate a random RFC 4122 version 4 UUID.
 *
 * Built from {@link generateRandomBytes} rather than `crypto.randomUUID`, which
 * is absent from some React Native runtimes this package supports, the same
 * reason `generateRandomBytes` resolves its source across three runtimes. All
 * 122 free bits come from the secure random source.
 */
export async function generateUuidV4(): Promise<string> {
  const bytes = await generateRandomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // variant 10xx
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}
