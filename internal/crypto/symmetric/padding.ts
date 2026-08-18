/**
 * ISO/IEC 7816-4 Message Padding (Length Hiding)
 *
 * Pads messages to fixed bucket sizes to prevent traffic analysis.
 * Applied at the application-message layer before AES-CBC encryption.
 *
 * Signal Protocol uses two-layer padding:
 * 1. Application layer: ISO/IEC 7816-4 (this module) - pads to 160-byte buckets
 * 2. Encryption layer: PKCS#7 (via WebCrypto AES-CBC) - pads to 16-byte blocks
 *
 * @see https://signal.org/docs/specifications/doubleratchet/ (Section 7.2)
 */

/**
 * Bucket size for padding (160 bytes).
 * Application-message padding bucket size.
 */
export {};
export const PADDING_BUCKET_SIZE = 160;

/**
 * ISO/IEC 7816-4 terminator byte.
 * Binary: 10000000 - single 1-bit followed by zeros.
 */
const PADDING_TERMINATOR = 0x80;

/**
 * Pad message using ISO/IEC 7816-4 bit padding.
 *
 * Adds 0x80 terminator followed by zero bytes to next bucket boundary.
 * This hides message length from traffic analysis.
 *
 * @param message - Original message bytes
 * @returns Padded message (multiple of PADDING_BUCKET_SIZE bytes)
 *
 * @example
 * ```typescript
 * const msg = new TextEncoder().encode('Hello');
 * const padded = padMessage(msg);
 * console.log(padded.length); // 160 (one bucket)
 * ```
 */
export function padMessage(message: Uint8Array): Uint8Array {
  // Calculate padded length (next bucket boundary)
  // +1 gives at least 1 byte of padding (the terminator)
  const paddedLength = Math.ceil((message.length + 1) / PADDING_BUCKET_SIZE) * PADDING_BUCKET_SIZE;

  // Allocate padded buffer (Uint8Array initializes to zeros)
  const padded = new Uint8Array(paddedLength);

  // Copy original message
  padded.set(message);

  // Add terminator byte after message
  padded[message.length] = PADDING_TERMINATOR;

  // Remaining bytes are already 0x00 (Uint8Array default)

  return padded;
}

/**
 * Remove ISO/IEC 7816-4 padding.
 *
 * Finds 0x80 terminator from end and returns original message.
 * Validates that all bytes after terminator are zeros.
 *
 * @param padded - Padded message bytes
 * @returns Original message bytes (padding removed)
 * @throws Error with generic message if padding is invalid
 *
 * @example
 * ```typescript
 * const original = new TextEncoder().encode('Hello');
 * const padded = padMessage(original);
 * const restored = unpadMessage(padded);
 * // restored equals original
 * ```
 */
export function unpadMessage(padded: Uint8Array): Uint8Array {
  // Scan from end to find 0x80 terminator
  // All bytes after terminator must be 0x00
  let terminatorIndex = -1;

  for (let i = padded.length - 1; i >= 0; i--) {
    const byte = padded[i];

    if (byte === PADDING_TERMINATOR) {
      terminatorIndex = i;
      break;
    }

    // Any non-zero byte before finding terminator is invalid
    if (byte !== 0x00) {
      // Generic error - do not reveal position or type of error
      // This prevents padding oracle attacks
      throw new Error('Invalid padding');
    }
  }

  // No terminator found
  if (terminatorIndex === -1) {
    throw new Error('Invalid padding');
  }

  // Return original message (everything before terminator)
  return padded.slice(0, terminatorIndex);
}
