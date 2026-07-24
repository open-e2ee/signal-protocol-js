/**
 * AES-GCM-HKDF Streaming AEAD
 *
 * Implements Google Tink's streaming authenticated encryption format.
 * Each segment is independently authenticated, enabling:
 * - Streaming decryption without loading entire file
 * - Per-chunk integrity verification
 * - Truncation detection via last-segment flag
 *
 * Wire Format (Tink AES256_GCM_HKDF_1MB aligned):
 *
 * CIPHERTEXT STRUCTURE:
 * ┌─────────────────────────────────────────────────────────────┐
 * │ Header (40 bytes)                                           │
 * │ ├── length: 1 byte (always 40 for AES-256)                  │
 * │ ├── salt: 32 bytes (random, for HKDF)                       │
 * │ └── noncePrefix: 7 bytes (random, part of GCM nonce)        │
 * ├─────────────────────────────────────────────────────────────┤
 * │ Segment 0: ciphertext || authTag (16 bytes)                 │
 * │   Max size: segmentSize - headerLength (first segment)      │
 * ├─────────────────────────────────────────────────────────────┤
 * │ Segment 1..N-1: ciphertext || authTag (16 bytes)            │
 * │   Max size: segmentSize (subsequent segments)               │
 * ├─────────────────────────────────────────────────────────────┤
 * │ Segment N (last): ciphertext || authTag (16 bytes)          │
 * │   Nonce has lastSegment=0x01 for truncation detection       │
 * └─────────────────────────────────────────────────────────────┘
 *
 * GCM NONCE (12 bytes):
 * ┌─────────────────┬──────────────────┬─────────────────┐
 * │ noncePrefix (7) │ segmentIndex (4) │ lastSegment (1) │
 * └─────────────────┴──────────────────┴─────────────────┘
 *
 * Security Properties:
 * - Authenticated encryption: Each chunk verified independently
 * - Truncation detection: Last segment flag in nonce
 * - Nonce uniqueness: Salt + counter + lastFlag ensures no reuse
 * - Key separation: HKDF derives per-stream key from master key
 *
 * @see https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming
 * @see https://eprint.iacr.org/2020/1019.pdf (Security analysis)
 */

import { hkdf } from '../kdf/hkdf';
import { aesGcmEncryptWithIVBytes, aesGcmDecryptWithIVBytes } from './aes';
import { generateRandomBytes } from '../random';
import { secureZeroBytes, concatBytes } from '../utils';

// ============================================================================
// Constants (Tink-aligned)
// ============================================================================

/** Header: 1 byte length + 32 byte salt + 7 byte nonce prefix */
export {};
export const STREAMING_HEADER_LENGTH = 40;

/** Salt length for HKDF key derivation */
export const STREAMING_SALT_LENGTH = 32;

/** Nonce prefix length (part of 12-byte GCM nonce) */
export const STREAMING_NONCE_PREFIX_LENGTH = 7;

/** GCM authentication tag length */
export const STREAMING_AUTH_TAG_LENGTH = 16;

/** GCM nonce is 12 bytes: 7 prefix + 4 counter + 1 lastSegment flag */
export const STREAMING_NONCE_LENGTH = 12;

/** Default 1MB segments (Tink's AES256_GCM_HKDF_1MB) */
export const DEFAULT_SEGMENT_SIZE = 1024 * 1024; // 1MB ciphertext segments

/** Minimum segment size: header (40) + authTag (16) + at least 1 byte plaintext */
export const MIN_SEGMENT_SIZE = STREAMING_HEADER_LENGTH + STREAMING_AUTH_TAG_LENGTH + 1; // 57 bytes

/** Maximum segment index (32-bit unsigned integer limit) */
const MAX_SEGMENT_INDEX = 0xffffffff; // ~4 petabytes with 1MB segments

/** HKDF info string for streaming AEAD key derivation */
const STREAMING_HKDF_INFO = new TextEncoder().encode('attachment');

// ============================================================================
// Types
// ============================================================================

export interface StreamingEncryptResult {
  /** Complete ciphertext (header + all segments) */
  ciphertext: Uint8Array;
  /** Segment size used (for metadata) */
  segmentSize: number;
}

export interface StreamingDecryptOptions {
  /** Expected segment size (from metadata). Defaults to 1MB. */
  segmentSize?: number;
}

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Encrypt data using AES-GCM-HKDF Streaming
 *
 * @param key - 32-byte AES-256 master key
 * @param plaintext - Data to encrypt
 * @param associatedData - Optional AAD for HKDF info parameter
 * @param segmentSize - Ciphertext segment size (default 1MB)
 * @returns Encrypted result with ciphertext and segment size
 */
export async function streamingEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0),
  segmentSize: number = DEFAULT_SEGMENT_SIZE
): Promise<StreamingEncryptResult> {
  if (key.length !== 32) {
    throw new Error('Streaming AEAD requires 32-byte key');
  }
  if (segmentSize < MIN_SEGMENT_SIZE) {
    throw new Error(`Segment size must be at least ${MIN_SEGMENT_SIZE} bytes`);
  }

  // 1. Generate random salt and nonce prefix
  const salt = await generateRandomBytes(STREAMING_SALT_LENGTH);
  const noncePrefix = await generateRandomBytes(STREAMING_NONCE_PREFIX_LENGTH);

  // 2. Derive per-stream key using HKDF
  // Combine associated data with default info string if provided
  const info =
    associatedData.length > 0
      ? concatBytes(STREAMING_HKDF_INFO, associatedData)
      : STREAMING_HKDF_INFO;
  const derivedKey = await hkdf(key, salt, info, 32);

  try {
    // 3. Build header: length || salt || noncePrefix
    const header = new Uint8Array(STREAMING_HEADER_LENGTH);
    header[0] = STREAMING_HEADER_LENGTH;
    header.set(salt, 1);
    header.set(noncePrefix, 1 + STREAMING_SALT_LENGTH);

    // 4. Calculate segment parameters
    // First segment: smaller due to header taking space in the first "block"
    // Plaintext that fits in first segment = segmentSize - header - authTag
    const firstSegmentPlaintext = segmentSize - STREAMING_HEADER_LENGTH - STREAMING_AUTH_TAG_LENGTH;
    // Subsequent segments: segmentSize - authTag
    const subsequentSegmentPlaintext = segmentSize - STREAMING_AUTH_TAG_LENGTH;

    // 5. Split plaintext into segments and encrypt
    const segments: Uint8Array[] = [header];
    let offset = 0;
    let segmentIndex = 0;

    while (offset < plaintext.length) {
      // Prevent segment index overflow (32-bit limit)
      if (segmentIndex > MAX_SEGMENT_INDEX) {
        throw new Error('File too large: maximum segment count exceeded');
      }

      // Calculate max plaintext for this segment
      const maxPlaintext = segmentIndex === 0 ? firstSegmentPlaintext : subsequentSegmentPlaintext;
      const segmentPlaintext = plaintext.slice(offset, offset + maxPlaintext);
      const isLastSegment = offset + segmentPlaintext.length >= plaintext.length;

      // Build nonce: noncePrefix (7) || segmentIndex (4 BE) || isLast (1)
      const nonce = buildNonce(noncePrefix, segmentIndex, isLastSegment);

      // Encrypt segment with AES-GCM (returns ciphertext || authTag)
      const segmentCiphertext = await aesGcmEncryptWithIVBytes(derivedKey, segmentPlaintext, nonce);

      segments.push(segmentCiphertext);
      offset += segmentPlaintext.length;
      segmentIndex++;
    }

    // Handle empty plaintext (still need one segment with empty ciphertext)
    if (plaintext.length === 0) {
      const nonce = buildNonce(noncePrefix, 0, true);
      const segmentCiphertext = await aesGcmEncryptWithIVBytes(
        derivedKey,
        new Uint8Array(0),
        nonce
      );
      segments.push(segmentCiphertext);
    }

    // 6. Concatenate all segments
    const ciphertext = concatBytes(...segments);

    return { ciphertext, segmentSize };
  } finally {
    // CRITICAL: Always zero derived key material
    secureZeroBytes(derivedKey);
  }
}

/**
 * Decrypt data using AES-GCM-HKDF Streaming
 *
 * @param key - 32-byte AES-256 master key (same as encryption)
 * @param ciphertext - Complete ciphertext (header + segments)
 * @param associatedData - Optional AAD (must match encryption)
 * @param options - Decryption options
 * @returns Decrypted plaintext
 * @throws Error if decryption fails or stream is truncated
 */
export async function streamingDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0),
  options: StreamingDecryptOptions = {}
): Promise<Uint8Array> {
  const segmentSize = options.segmentSize ?? DEFAULT_SEGMENT_SIZE;

  if (key.length !== 32) {
    throw new Error('Streaming AEAD requires 32-byte key');
  }
  if (segmentSize < MIN_SEGMENT_SIZE) {
    throw new Error(`Segment size must be at least ${MIN_SEGMENT_SIZE} bytes`);
  }

  // 1. Parse header
  if (ciphertext.length < STREAMING_HEADER_LENGTH) {
    throw new Error('Ciphertext too short for header');
  }

  const headerLength = ciphertext[0];
  if (headerLength !== STREAMING_HEADER_LENGTH) {
    throw new Error(`Invalid header length: ${headerLength}`);
  }

  const salt = ciphertext.slice(1, 1 + STREAMING_SALT_LENGTH);
  const noncePrefix = ciphertext.slice(1 + STREAMING_SALT_LENGTH, STREAMING_HEADER_LENGTH);

  // 2. Derive per-stream key using HKDF
  const info =
    associatedData.length > 0
      ? concatBytes(STREAMING_HKDF_INFO, associatedData)
      : STREAMING_HKDF_INFO;
  const derivedKey = await hkdf(key, salt, info, 32);

  try {
    // 3. Decrypt segments
    const segments: Uint8Array[] = [];
    let offset = STREAMING_HEADER_LENGTH;
    let segmentIndex = 0;
    let foundLastSegment = false;

    // Calculate expected segment sizes
    const firstSegmentCiphertextSize = segmentSize - STREAMING_HEADER_LENGTH;
    const subsequentSegmentCiphertextSize = segmentSize;

    while (offset < ciphertext.length) {
      // Prevent segment index overflow (32-bit limit)
      if (segmentIndex > MAX_SEGMENT_INDEX) {
        throw new Error('Ciphertext too large: maximum segment count exceeded');
      }

      // Calculate expected ciphertext size for this segment
      const expectedCiphertextSize =
        segmentIndex === 0 ? firstSegmentCiphertextSize : subsequentSegmentCiphertextSize;

      // Calculate actual segment size (might be smaller for last segment)
      const remainingBytes = ciphertext.length - offset;
      const segmentCiphertextSize = Math.min(expectedCiphertextSize, remainingBytes);

      // Minimum segment size is authTag length (for empty plaintext segment)
      if (segmentCiphertextSize < STREAMING_AUTH_TAG_LENGTH) {
        throw new Error(`Segment ${segmentIndex} too small: ${segmentCiphertextSize} bytes`);
      }

      const segmentCiphertext = ciphertext.slice(offset, offset + segmentCiphertextSize);

      // Determine if this is the last segment
      const isLastSegment = offset + segmentCiphertextSize >= ciphertext.length;

      // Build nonce (must match encryption)
      const nonce = buildNonce(noncePrefix, segmentIndex, isLastSegment);

      // Decrypt segment - this verifies the authTag
      try {
        const segmentPlaintext = await aesGcmDecryptWithIVBytes(
          derivedKey,
          segmentCiphertext,
          nonce
        );
        segments.push(segmentPlaintext);
      } catch {
        throw new Error(`Segment ${segmentIndex} decryption failed: authentication error`);
      }

      if (isLastSegment) {
        foundLastSegment = true;
      }

      offset += segmentCiphertextSize;
      segmentIndex++;
    }

    // 4. Verify we found the last segment (truncation detection)
    if (!foundLastSegment) {
      throw new Error('Stream truncated: last segment flag not found');
    }

    // 5. Concatenate plaintext segments
    return concatBytes(...segments);
  } finally {
    // CRITICAL: Always zero derived key material
    secureZeroBytes(derivedKey);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Build 12-byte GCM nonce from components
 *
 * Format: noncePrefix (7) || segmentIndex (4 BE) || lastSegment (1)
 *
 * @param prefix - 7-byte nonce prefix
 * @param segmentIndex - Segment counter (0-based)
 * @param isLastSegment - True if this is the last segment
 * @returns 12-byte nonce for GCM
 */
function buildNonce(prefix: Uint8Array, segmentIndex: number, isLastSegment: boolean): Uint8Array {
  const nonce = new Uint8Array(STREAMING_NONCE_LENGTH);

  // 7 bytes: nonce prefix
  nonce.set(prefix, 0);

  // 4 bytes: segment index (big-endian)
  nonce[7] = (segmentIndex >>> 24) & 0xff;
  nonce[8] = (segmentIndex >>> 16) & 0xff;
  nonce[9] = (segmentIndex >>> 8) & 0xff;
  nonce[10] = segmentIndex & 0xff;

  // 1 byte: last segment flag
  nonce[11] = isLastSegment ? 0x01 : 0x00;

  return nonce;
}
