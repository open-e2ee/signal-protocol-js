/**
 * Fuzzes the persistent session-record JSON codec: the seam every storage
 * adapter crosses when it reads a session back from disk. `SyntaxError` is
 * part of the contract here because the codec parses with `JSON.parse`.
 */
import { deserializeSessionRecord } from '../dist/local/store/session-codec.js';
import { allowOnlyControlledError } from './controlled-error.js';

export function fuzz(data) {
  const json = data.toString('utf8');
  try {
    deserializeSessionRecord(json);
  } catch (error) {
    allowOnlyControlledError(error, [SyntaxError]);
  }
}
