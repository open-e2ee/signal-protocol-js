export async function hostRandomBytes(size: number): Promise<Uint8Array> {
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues) {
    throw new Error('No cryptographically secure random source is available in this runtime.');
  }
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(size, offset + 65_536)));
  }
  return bytes;
}
