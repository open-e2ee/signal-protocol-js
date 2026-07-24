/**
 * Encoding Module (Public API)
 *
 * Provides base64, hex, and byte encoding utilities for app code
 * outside of the public package This is the public boundary for encoding
 * functions -- app code should import from here rather than from
 * the public package
 *
 * @example
 * ```typescript
 * import { bytesToBase64, bytesToHex, stringToBytes } from './';
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
} from './base64';

export { bytesToHex, hexToBytes } from './hex';
