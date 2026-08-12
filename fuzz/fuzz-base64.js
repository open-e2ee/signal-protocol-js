/**
 * Fuzzes the base64 conversions with two obligations: arbitrary strings must
 * be rejected with a controlled error, and every byte sequence must survive
 * the encode/decode round trip bit-for-bit, in both the standard and the
 * URL-safe alphabet.
 */
import {
  bytesToBase64,
  base64ToBytes,
  bytesToUrlSafeBase64,
  base64ToUrlSafe,
  urlSafeToBase64,
} from '../dist/internal/crypto/utils.js';
import { allowOnlyControlledError } from './controlled-error.js';

function assertSameBytes(expected, actual, label) {
  if (expected.length !== actual.length) {
    throw new Error(`${label}: length ${expected.length} became ${actual.length}`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (expected[index] !== actual[index]) {
      throw new Error(`${label}: byte ${index} changed`);
    }
  }
}

export function fuzz(data) {
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

  const base64 = bytesToBase64(bytes);
  assertSameBytes(bytes, base64ToBytes(base64), 'standard round trip');

  const urlSafe = bytesToUrlSafeBase64(bytes);
  if (base64ToUrlSafe(base64) !== urlSafe) {
    throw new Error('URL-safe conversions disagree about the same bytes');
  }
  assertSameBytes(bytes, base64ToBytes(urlSafeToBase64(urlSafe)), 'URL-safe round trip');

  const arbitrary = data.toString('latin1');
  try {
    base64ToBytes(arbitrary);
  } catch (error) {
    allowOnlyControlledError(error);
  }
  try {
    base64ToBytes(urlSafeToBase64(arbitrary));
  } catch (error) {
    allowOnlyControlledError(error);
  }
}
