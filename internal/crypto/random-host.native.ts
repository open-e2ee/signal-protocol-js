export async function hostRandomBytes(size: number): Promise<Uint8Array> {
  const crypto = globalThis.crypto;
  const bytes = new Uint8Array(size);
  if (crypto?.getRandomValues) {
    for (let offset = 0; offset < size; offset += 65_536) {
      crypto.getRandomValues(bytes.subarray(offset, Math.min(size, offset + 65_536)));
    }
    return bytes;
  }

  const { getRandomBytesAsync } = await import('expo-crypto');
  for (let offset = 0; offset < size; offset += 1024) {
    bytes.set(await getRandomBytesAsync(Math.min(1024, size - offset)), offset);
  }
  return bytes;
}
