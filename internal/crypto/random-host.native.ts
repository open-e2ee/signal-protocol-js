import { getRandomBytesAsync } from 'expo-crypto';

export async function hostRandomBytes(size: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 1024) {
    bytes.set(await getRandomBytesAsync(Math.min(1024, size - offset)), offset);
  }
  return bytes;
}
