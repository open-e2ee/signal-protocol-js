/**
 * Keyed index hashes for stores that encrypt their records.
 *
 * A store that encrypts a record still needs clear fields to find and delete
 * it. Each such field is an HMAC-SHA-256 under one subkey of the store key, so
 * the store holds no raw group ID, account ID, or device in the clear. Every
 * index of a store uses the same subkey, so one group has one group hash in
 * the receive queue and in the handoff ledger.
 */

import { bytesToBase64, hkdf, hmac } from '../../internal/crypto';

const SUBKEY_INFO = new TextEncoder().encode('OpenE2EE receive-work blocked group v1');

/**
 * The HMAC subkey of one store key. Derive it again after each replacement
 * of the store key.
 */
export function keyedIndexSubkey(storeKey: Uint8Array): Promise<Uint8Array> {
  return hkdf(storeKey, new Uint8Array(0), SUBKEY_INFO, 32);
}

/** The keyed hash of one group ID: an HMAC of the UTF-8 group ID. */
export function keyedGroupHash(subkey: Uint8Array, groupId: string): string {
  return bytesToBase64(hmac(subkey, new TextEncoder().encode(groupId)));
}

/**
 * The keyed hash of a labeled field list. Each field is its UTF-8 bytes after
 * a 4-byte big-endian length, and the label is the first field, so two lists
 * hash equal only when every field is equal. A number is its decimal string.
 */
export function keyedFieldsHash(
  subkey: Uint8Array,
  label: string,
  fields: readonly (string | number)[]
): string {
  const encoder = new TextEncoder();
  const parts = [label, ...fields].map((field) => encoder.encode(String(field)));
  const bytes = new Uint8Array(parts.reduce((total, part) => total + 4 + part.length, 0));
  const view = new DataView(bytes.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length);
    bytes.set(part, offset + 4);
    offset += 4 + part.length;
  }
  return bytesToBase64(hmac(subkey, bytes));
}
