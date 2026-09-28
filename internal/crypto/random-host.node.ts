import { webcrypto } from 'node:crypto';

export function hostRandomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65_536) {
    webcrypto.getRandomValues(bytes.subarray(offset, Math.min(size, offset + 65_536)));
  }
  return bytes;
}
