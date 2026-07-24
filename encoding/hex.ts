/**
 * Hex Encoding Utilities (Public API)
 *
 * Re-exports hex encoding functions from @noble/hashes for
 * consistent usage across the app.
 *
 * @example
 * ```typescript
 * import { bytesToHex, hexToBytes } from './';
 * ```
 */
export {};
export { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
