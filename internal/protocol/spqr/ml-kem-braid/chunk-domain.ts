/**
 * Canonical ML-KEM Braid chunk-index domain.
 *
 * The pinned SPQR reference stores `Chunk.index` as a
 * `u16`, accepts every value through `u16::MAX`, and uses that value directly
 * as the GF(2^16) evaluation point. GF(2^16) therefore supplies 65,536 chunk
 * indexes, 0...65,535. The encoder cursor is the next index to emit, so its
 * terminal value is one past the maximum chunk index.
 *
 * The pinned reference's `next_chunk` casts its wider cursor to `u16`; another
 * call after index 65,535 could therefore wrap to a duplicate index zero. This
 * SDK deliberately fails closed at the terminal cursor instead of reproducing
 * that unchecked wrap. It does not exclude any distinct GF(2^16) point.
 *
 * Keep this implementation invariant separate from frozen specification
 * snapshots so every mutable wire, state, and Reed-Solomon boundary shares one
 * executable authority.
 */

/** Number of distinct GF(2^16) evaluation points. */
export const BRAID_CHUNK_POINT_COUNT = 0x1_0000;

/** Largest valid Braid chunk index (`u16::MAX`). */
export const BRAID_CHUNK_INDEX_MAX = BRAID_CHUNK_POINT_COUNT - 1;

/** Largest valid next-chunk cursor after all evaluation points were emitted. */
export const BRAID_ENCODER_CURSOR_MAX = BRAID_CHUNK_POINT_COUNT;

/** Validate an attacker-controlled Braid chunk index. */
export function assertBraidChunkIndex(value: unknown, label = 'Braid chunk index'): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > BRAID_CHUNK_INDEX_MAX
  ) {
    throw new Error(`${label} must be an integer between 0 and ${BRAID_CHUNK_INDEX_MAX}`);
  }
  return value as number;
}

/** Validate a persisted next-chunk cursor, including the exhausted terminal value. */
export function assertBraidEncoderCursor(
  value: unknown,
  label = 'Braid encoder cursor'
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > BRAID_ENCODER_CURSOR_MAX
  ) {
    throw new Error(`${label} must be an integer between 0 and ${BRAID_ENCODER_CURSOR_MAX}`);
  }
  return value as number;
}
