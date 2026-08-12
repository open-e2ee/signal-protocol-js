/**
 * Fuzzes the Signal Protocol wire-message decoders: the seam every inbound
 * ciphertext crosses before any cryptographic processing.
 */
import {
  decodeSignalProtocolMessage,
  decodePreKeySignalProtocolMessage,
} from '../dist/internal/encoding/proto/signal-message.js';
import { allowOnlyControlledError } from './controlled-error.js';

export function fuzz(data) {
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (bytes.length === 0) return;
  const payload = bytes.subarray(1);
  try {
    if (bytes[0] % 2 === 0) {
      decodeSignalProtocolMessage(payload);
    } else {
      decodePreKeySignalProtocolMessage(payload);
    }
  } catch (error) {
    allowOnlyControlledError(error);
  }
}
