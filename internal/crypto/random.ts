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
