/**
 * Secure Random Number Generation
 *
 * Provides cryptographically secure random bytes using Web Crypto when
 * available, with Node and Expo fallbacks for non-browser runtimes.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 */

/**
 * Generate cryptographically secure random bytes
 *
 * Resolution order:
 * - `globalThis.crypto.getRandomValues` (browser / modern Node / many RN runtimes)
 * - `node:crypto.webcrypto` (Node fallback)
 * - `expo-crypto.getRandomBytesAsync` (Expo fallback)
 *
 * @param size Number of random bytes to generate
 * @returns Promise resolving to random bytes
 */
export {};
const MAX_GET_RANDOM_VALUES_BYTES = 65_536;

function fillRandomBytes(
  fillChunk: (buffer: Uint8Array<ArrayBuffer>) => void,
  size: number
): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += MAX_GET_RANDOM_VALUES_BYTES) {
    const chunkSize = Math.min(size - offset, MAX_GET_RANDOM_VALUES_BYTES);
    const chunk = new Uint8Array(new ArrayBuffer(chunkSize));
    fillChunk(chunk);
    bytes.set(chunk, offset);
  }
  return bytes;
}

export async function generateRandomBytes(size: number): Promise<Uint8Array> {
  const webCrypto = globalThis.crypto;
  if (webCrypto?.getRandomValues) {
    return fillRandomBytes((buffer) => {
      webCrypto.getRandomValues(buffer);
    }, size);
  }

  try {
    const { webcrypto } = await import('node:crypto');
    return fillRandomBytes((buffer) => {
      webcrypto.getRandomValues(buffer);
    }, size);
  } catch {
    // Ignore and fall through to Expo fallback.
  }

  try {
    const expoCrypto = await import('expo-crypto');
    return await expoCrypto.getRandomBytesAsync(size);
  } catch {
    throw new Error(
      'No cryptographically secure random source available. ' +
        'Provide Web Crypto, Node crypto, or Expo Crypto in this runtime.'
    );
  }
}

/**
 * Generate a random RFC 4122 version 4 UUID.
 *
 * Built from {@link generateRandomBytes} rather than `crypto.randomUUID`, which
 * is absent from some React Native runtimes this package supports — the same
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
