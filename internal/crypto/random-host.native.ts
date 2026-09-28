import { SecureRandomUnavailableError } from '../../types/errors';

/**
 * React Native reads only the global `crypto.getRandomValues`. Hermes has none
 * yet, so the app must install a provider. The SDK imports no provider itself:
 * Metro fails the bundle of an app that lacks the package, even inside a `try`.
 */
export function hostRandomBytes(size: number): Uint8Array {
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues) {
    throw new SecureRandomUnavailableError(
      'No global crypto.getRandomValues is available in this React Native runtime. ' +
        'Install react-native-get-random-values 2.x or react-native-quick-crypto, ' +
        'and load it at app startup before the first SDK call.'
    );
  }
  const bytes = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(size, offset + 65_536)));
  }
  return bytes;
}
