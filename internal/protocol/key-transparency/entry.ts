/**
 * The value of an identity log entry, the bytes that its commitment opens
 * to:
 *
 *   u8 kind (1 key, 0 tombstone) || u32be version || u64be recorded time
 *   (milliseconds) || identity bytes (key entries only)
 *
 * The version counts the entries of one account from 1. The identity bytes
 * are the encoded composite identity that the account registered.
 */

/** A decoded identity log entry. */
export type IdentityLogEntry =
  | {
      readonly kind: 'key';
      readonly version: number;
      readonly recordedAt: number;
      readonly identity: Uint8Array;
    }
  | {
      readonly kind: 'tombstone';
      readonly version: number;
      readonly recordedAt: number;
    };

const HEADER_BYTES = 13;
const KEY_KIND = 1;
const TOMBSTONE_KIND = 0;

/** Decodes an entry value. Returns `null` for a value that is not an entry. */
export function decodeIdentityLogEntry(value: Uint8Array): IdentityLogEntry | null {
  if (value.length < HEADER_BYTES) return null;
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const kind = value[0];
  const version = view.getUint32(1, false);
  const recordedAt = view.getBigUint64(5, false);
  if (version < 1 || recordedAt > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  if (kind === TOMBSTONE_KIND) {
    if (value.length !== HEADER_BYTES) return null;
    return { kind: 'tombstone', version, recordedAt: Number(recordedAt) };
  }
  if (kind === KEY_KIND) {
    if (value.length === HEADER_BYTES) return null;
    return {
      kind: 'key',
      version,
      recordedAt: Number(recordedAt),
      identity: value.slice(HEADER_BYTES),
    };
  }
  return null;
}
