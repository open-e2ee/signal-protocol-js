/**
 * The commitment of an identity log entry:
 *
 *   HMAC-SHA256(fixed key, opening || u16be(len(search key)) || search key
 *               || u32be(len(value)) || value)
 *
 * The fixed key and the input order are those of the Signal key transparency
 * commitment. The opening is 16 bytes. The length prefixes stop a shift of
 * bytes from the search key to the value.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const COMMITMENT_KEY = Uint8Array.of(
  0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5
);

/** The bytes of a commitment opening. */
export const COMMITMENT_OPENING_BYTES = 16;

const MAXIMUM_SEARCH_KEY_BYTES = 0xffff;
const MAXIMUM_VALUE_BYTES = 0xffffffff;

/**
 * Returns the 32-byte commitment to `value` under the search key and the
 * opening, or `null` when an input has a length that the encoding cannot
 * carry.
 */
export function commitIdentityLogValue(
  searchKey: Uint8Array,
  value: Uint8Array,
  opening: Uint8Array
): Uint8Array | null {
  if (
    opening.length !== COMMITMENT_OPENING_BYTES ||
    searchKey.length > MAXIMUM_SEARCH_KEY_BYTES ||
    value.length > MAXIMUM_VALUE_BYTES
  ) {
    return null;
  }
  const lengths = new Uint8Array(6);
  const view = new DataView(lengths.buffer);
  view.setUint16(0, searchKey.length, false);
  view.setUint32(2, value.length, false);
  return hmac
    .create(sha256, COMMITMENT_KEY)
    .update(opening)
    .update(lengths.subarray(0, 2))
    .update(searchKey)
    .update(lengths.subarray(2))
    .update(value)
    .digest();
}
