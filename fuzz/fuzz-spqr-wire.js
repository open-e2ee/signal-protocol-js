/**
 * Fuzzes the post-quantum ratchet wire decoder and the shard binary format
 * used by the ML-KEM braid.
 */
import { decodeSPQRWire } from '../dist/internal/encoding/proto/pq-ratchet-serialize.js';
import { deserializeShardBinary } from '../dist/internal/protocol/spqr/ml-kem-braid/serialize.js';
import { allowOnlyControlledError } from './controlled-error.js';

export function fuzz(data) {
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (bytes.length === 0) return;
  const payload = bytes.subarray(1);
  try {
    if (bytes[0] % 2 === 0) {
      decodeSPQRWire(payload);
    } else {
      deserializeShardBinary(payload);
    }
  } catch (error) {
    allowOnlyControlledError(error);
  }
}
