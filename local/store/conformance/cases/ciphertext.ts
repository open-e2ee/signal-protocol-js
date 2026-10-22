/**
 * The ciphertext case: a store that declares a cipher keeps no known
 * plaintext in its stored bytes.
 */

import { fail } from '../checks';
import { PLAINTEXT_MARKER, receiveWork, senderKeyState } from '../records';
import type { LocalStoreConformanceCase } from '../types';

/** The bytes of an ASCII text. The marker is ASCII, so this is its UTF-8 form. */
function asciiBytes(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index);
  return bytes;
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  const last = haystack.length - needle.length;
  for (let start = 0; start <= last; start += 1) {
    let index = 0;
    while (index < needle.length && haystack[start + index] === needle[index]) index += 1;
    if (index === needle.length) return true;
  }
  return false;
}

export const ciphertextCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'no plaintext at rest',
    needs: 'readRawBytes',
    applies: function declaresCipher(store) {
      const protection = store.protection;
      return (
        protection !== null &&
        protection !== undefined &&
        protection.atRest !== undefined &&
        protection.atRest !== 'none'
      );
    },
    run: async function noPlaintextAtRest(context) {
      const store = context.store;
      await store.putReceiveWork(
        receiveWork('conformance-cipher-work', { plaintext: PLAINTEXT_MARKER }),
        null
      );
      await store.setMetadata('conformance-cipher-metadata', PLAINTEXT_MARKER);
      await store.storeSenderKeyRecord('conformance-cipher-group', 'conformance-cipher-member', 1, [
        senderKeyState(1, PLAINTEXT_MARKER),
      ]);
      const needle = asciiBytes(PLAINTEXT_MARKER);
      const chunks = await context.readRawBytes();
      if (chunks.length === 0) fail('readRawBytes returned no bytes');
      chunks.forEach(function scan(chunk, index) {
        if (contains(chunk, needle)) {
          fail('stored chunk ' + index + ' holds the plaintext marker');
        }
      });
    },
  },
];
