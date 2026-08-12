/**
 * Fuzzes the group-messaging wire decoders: sender-key messages and the
 * distribution messages that establish them.
 */
import {
  decodeSenderKeyMessage,
  decodeSenderKeyDistributionMessage,
} from '../dist/internal/encoding/proto/sender-key-message.js';
import { allowOnlyControlledError } from './controlled-error.js';

export function fuzz(data) {
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (bytes.length === 0) return;
  const payload = bytes.subarray(1);
  try {
    if (bytes[0] % 2 === 0) {
      decodeSenderKeyMessage(payload);
    } else {
      decodeSenderKeyDistributionMessage(payload);
    }
  } catch (error) {
    allowOnlyControlledError(error);
  }
}
