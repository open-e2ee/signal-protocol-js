/**
 * Base64 and Byte Encoding Utilities (Public API)
 *
 * Re-exports encoding functions from the internal crypto module
 * for use by app code outside of the public package
 *
 * @example
 * ```typescript
 * import { bytesToBase64, base64ToBytes, stringToBytes } from './';
 * ```
 */
export {};
export {
  bytesToBase64,
  base64ToBytes,
  bytesToUrlSafeBase64,
  base64ToUrlSafe,
  urlSafeToBase64,
  stringToBytes,
  bytesToString,
  concatBytes,
} from '../internal/crypto/utils';
