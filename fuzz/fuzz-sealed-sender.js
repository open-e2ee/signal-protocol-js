/**
 * Fuzzes the sealed-sender envelope decoders: certificates and the
 * unidentified-sender message wrapper, all parsed before sender identity is
 * known.
 */
import {
  decodeUnidentifiedSenderMessage,
  decodeServerCertificate,
  decodeSenderCertificate,
} from '../dist/internal/protocol/sealed-sender/proto/index.js';
import { allowOnlyControlledError } from './controlled-error.js';

export function fuzz(data) {
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (bytes.length === 0) return;
  const payload = bytes.subarray(1);
  try {
    switch (bytes[0] % 3) {
      case 0:
        decodeUnidentifiedSenderMessage(payload);
        break;
      case 1:
        decodeServerCertificate(payload);
        break;
      default:
        decodeSenderCertificate(payload);
        break;
    }
  } catch (error) {
    allowOnlyControlledError(error);
  }
}
