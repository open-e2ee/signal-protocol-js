/**
 * Cryptographic Utility Functions
 *
 * Provides encoding/decoding, best-effort fixed-work comparison, and secure memory management.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#implementation-fingerprinting
 */

import { type Base64, asBase64 } from '../../types/utils';

// ============================================================================
// Encoding/Decoding Utilities
// ============================================================================

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP = (() => {
  const lookup = new Int16Array(256).fill(-1);
  for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
    lookup[BASE64_ALPHABET.charCodeAt(index)] = index;
  }
  return lookup;
})();

function bytesToBase64Portable(bytes: Uint8Array): string {
  let output = '';
  let offset = 0;

  for (; offset + 2 < bytes.length; offset += 3) {
    const value = (bytes[offset]! << 16) | (bytes[offset + 1]! << 8) | bytes[offset + 2]!;
    output +=
      BASE64_ALPHABET[(value >> 18) & 0x3f] +
      BASE64_ALPHABET[(value >> 12) & 0x3f] +
      BASE64_ALPHABET[(value >> 6) & 0x3f] +
      BASE64_ALPHABET[value & 0x3f];
  }

  if (offset < bytes.length) {
    const first = bytes[offset]!;
    const second = offset + 1 < bytes.length ? bytes[offset + 1]! : 0;
    const value = (first << 16) | (second << 8);
    output += BASE64_ALPHABET[(value >> 18) & 0x3f] + BASE64_ALPHABET[(value >> 12) & 0x3f];
    output += offset + 1 < bytes.length ? BASE64_ALPHABET[(value >> 6) & 0x3f] + '=' : '==';
  }

  return output;
}

function decodeBase64Char(character: string, index: number): number {
  const code = character.charCodeAt(0);
  const value = code < BASE64_LOOKUP.length ? BASE64_LOOKUP[code] : -1;
  if (value < 0) {
    throw new Error(`Invalid base64 character at offset ${index}`);
  }
  return value;
}

function base64ToBytesPortable(base64: string): Uint8Array {
  const normalized = base64.replace(/\s/g, '');
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  if (normalized.length % 4 !== 0) {
    throw new Error('Invalid base64 string length');
  }

  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  const output = new Uint8Array((normalized.length / 4) * 3 - padding);
  let outputOffset = 0;

  for (let inputOffset = 0; inputOffset < normalized.length; inputOffset += 4) {
    const isFinalChunk = inputOffset + 4 === normalized.length;
    const first = normalized[inputOffset]!;
    const second = normalized[inputOffset + 1]!;
    const third = normalized[inputOffset + 2]!;
    const fourth = normalized[inputOffset + 3]!;

    if (first === '=' || second === '=') {
      throw new Error('Invalid base64 padding');
    }
    if (!isFinalChunk && (third === '=' || fourth === '=')) {
      throw new Error('Invalid base64 padding');
    }
    if (third === '=' && fourth !== '=') {
      throw new Error('Invalid base64 padding');
    }
    if (third === '=' && padding !== 2) {
      throw new Error('Invalid base64 padding');
    }
    if (fourth === '=' && padding === 0) {
      throw new Error('Invalid base64 padding');
    }

    const firstValue = decodeBase64Char(first, inputOffset);
    const secondValue = decodeBase64Char(second, inputOffset + 1);
    const thirdValue = third === '=' ? 0 : decodeBase64Char(third, inputOffset + 2);
    const fourthValue = fourth === '=' ? 0 : decodeBase64Char(fourth, inputOffset + 3);

    if (isFinalChunk && padding === 2 && (secondValue & 0x0f) !== 0) {
      throw new Error('Invalid base64 padding bits');
    }
    if (isFinalChunk && padding === 1 && (thirdValue & 0x03) !== 0) {
      throw new Error('Invalid base64 padding bits');
    }

    const value = (firstValue << 18) | (secondValue << 12) | (thirdValue << 6) | fourthValue;

    if (outputOffset < output.length) {
      output[outputOffset] = (value >> 16) & 0xff;
      outputOffset += 1;
    }
    if (outputOffset < output.length) {
      output[outputOffset] = (value >> 8) & 0xff;
      outputOffset += 1;
    }
    if (outputOffset < output.length) {
      output[outputOffset] = value & 0xff;
      outputOffset += 1;
    }
  }

  return output;
}

/**
 * Convert Uint8Array to Base64 string
 */
export function bytesToBase64(bytes: Uint8Array): Base64 {
  return asBase64(bytesToBase64Portable(bytes));
}

/**
 * Convert Uint8Array to URL-safe Base64 string (RFC 4648 §5)
 *
 * URL-safe Base64 uses:
 * - `-` instead of `+`
 * - `_` instead of `/`
 * - No padding (`=`)
 *
 * Used for R2 storage keys (attachments, profiles), which must survive being
 * placed in a URL path without escaping.
 *
 * @see RFC 4648 Section 5 - Base 64 Encoding with URL and Filename Safe Alphabet
 */
export function bytesToUrlSafeBase64(bytes: Uint8Array): string {
  return stripBase64Padding(bytesToBase64Portable(bytes).replace(/\+/g, '-').replace(/\//g, '_'));
}

/**
 * Strip trailing `=` padding without a regular expression.
 *
 * A `/=+$/` replace backtracks quadratically on long runs of `=`, and these
 * conversions accept library input.
 */
function stripBase64Padding(base64: string): string {
  let end = base64.length;
  while (end > 0 && base64.charCodeAt(end - 1) === 0x3d /* '=' */) end--;
  return base64.slice(0, end);
}

/**
 * Convert standard base64 string to URL-safe base64 string (RFC 4648 §5)
 *
 * Use this when you already have a base64 string and need to make it URL-safe.
 * For converting bytes directly, use `bytesToUrlSafeBase64` instead.
 *
 * @param base64 - Standard base64 string
 * @returns URL-safe base64 string (no +, /, or = characters)
 */
export function base64ToUrlSafe(base64: string): string {
  return stripBase64Padding(base64.replace(/\+/g, '-').replace(/\//g, '_'));
}

/**
 * Convert URL-safe base64 string back to standard base64 string
 *
 * Restores padding and replaces URL-safe characters with standard base64 characters.
 *
 * @param urlSafe - URL-safe base64 string
 * @returns Standard base64 string with padding restored
 */
export function urlSafeToBase64(urlSafe: string): string {
  let base64 = urlSafe.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed (base64 must be multiple of 4)
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';

  return base64;
}

/**
 * Convert Base64 string to Uint8Array
 */
export function base64ToBytes(base64: Base64): Uint8Array {
  return base64ToBytesPortable(base64);
}

/**
 * Convert string to Uint8Array (UTF-8)
 */
export function stringToBytes(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Convert Uint8Array to string (UTF-8)
 */
export function bytesToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

// ============================================================================
// Best-effort fixed-work source patterns
// ============================================================================

/**
 * Best-effort fixed-work comparison for equal-length byte strings.
 *
 * Length is treated as public input: a mismatch is rejected after a fixed-size
 * dummy comparison instead of looping to the shorter attacker-controlled length.
 * JavaScript engines may still optimize this code in data-dependent ways, so this
 * must not be described as a hard constant-time guarantee. Native/WASM callers
 * should use a platform timing-safe primitive for secrets exposed to local timing.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    // Keep the mismatch path independent of either supplied length. The values
    // are volatile locals from the engine's point of view, but JS cannot promise
    // that a JIT will preserve this work; see the function-level caveat above.
    const dummyA = new Uint8Array(32);
    const dummyB = new Uint8Array(32);
    let dummyDifference = 0;
    for (let i = 0; i < 32; i++) {
      dummyDifference |= dummyA[i]! ^ dummyB[i]!;
    }
    return dummyDifference !== 0;
  }

  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i]! ^ b[i]!;
  }

  return difference === 0;
}

let checkedNativeClone: unknown;
let nativeCloneStaysInRealm = false;

/**
 * Does the ambient structuredClone hand back objects this realm recognizes?
 *
 * A structuredClone reached across a realm boundary — the arrangement a Node vm
 * context produces, and one Jest builds for everything it runs — returns a working
 * Map whose prototype belongs to the other realm. `instanceof Map` then reports
 * false everywhere downstream: the session codec writes such a Map as `{}`, and
 * the portable clone below rebuilds it as a prototype-only husk whose `size`
 * getter throws. Both losses are silent. The portable path constructs its Maps
 * here, so use it whenever the native clone would leave the realm.
 */
function isNativeCloneUsable(nativeClone: <U>(input: U) => U): boolean {
  if (nativeClone !== checkedNativeClone) {
    checkedNativeClone = nativeClone;
    try {
      nativeCloneStaysInRealm = nativeClone(new Map()) instanceof Map;
    } catch {
      nativeCloneStaysInRealm = false;
    }
  }
  return nativeCloneStaysInRealm;
}

/** Clone protocol state without losing bigint, typed arrays, Map, or cycles. */
export function cloneProtocolState<T>(value: T, forcePortableClone = false): T {
  const nativeClone = (
    globalThis as typeof globalThis & { structuredClone?: <U>(input: U) => U }
  ).structuredClone;
  if (!forcePortableClone && typeof nativeClone === 'function' && isNativeCloneUsable(nativeClone)) {
    return nativeClone(value);
  }

  const seen = new Map<object, unknown>();
  const clone = (input: unknown): unknown => {
    if (input === null || typeof input !== 'object') return input;
    if (seen.has(input)) return seen.get(input);
    if (input instanceof Uint8Array) return Uint8Array.from(input);
    if (input instanceof ArrayBuffer) return input.slice(0);
    if (ArrayBuffer.isView(input)) {
      const bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      return Uint8Array.from(bytes);
    }
    if (input instanceof Map) {
      const output = new Map<unknown, unknown>();
      seen.set(input, output);
      for (const [key, mapValue] of input) output.set(clone(key), clone(mapValue));
      return output;
    }
    if (input instanceof Set) {
      const output = new Set<unknown>();
      seen.set(input, output);
      for (const item of input) output.add(clone(item));
      return output;
    }
    if (Array.isArray(input)) {
      const output: unknown[] = [];
      seen.set(input, output);
      for (const item of input) output.push(clone(item));
      return output;
    }

    const output = Object.create(Object.getPrototypeOf(input)) as Record<PropertyKey, unknown>;
    seen.set(input, output);
    for (const key of Reflect.ownKeys(input)) {
      output[key] = clone((input as Record<PropertyKey, unknown>)[key]);
    }
    return output;
  };

  return clone(value) as T;
}

// ============================================================================
// Best-effort JavaScript key disposal
// ============================================================================

/**
 * Best-effort clearing of sensitive key material before deletion
 *
 * Signal Protocol Specification Section 8.1 -
 * "To securely delete a key, it is recommended to first overwrite the key
 * with random or zero data."
 *
 * This function attempts to zero base64-encoded keys before deletion
 * to prevent sensitive material from remaining in memory.
 *
 * **IMPORTANT: JavaScript String Immutability Limitation**
 *
 * Due to JavaScript's immutable string design, this function can only zero
 * the *decoded* Uint8Array copy, NOT the original base64 string itself.
 * The original base64 string remains in memory until garbage collected.
 *
 * This is a fundamental platform limitation - JavaScript provides no mechanism
 * to modify string contents in place. The original string bytes will persist
 * in the V8/JSC heap until the garbage collector runs, which is non-deterministic.
 *
 * **Defense in Depth Strategy:**
 * 1. We zero the decoded byte array (prevents some memory analysis attacks)
 * 2. We rely on timely garbage collection for the string
 * 3. We immediately delete from the database (removes persistent storage)
 * 4. The two-layer encryption architecture provides additional protection
 *
 * Deployments requiring stronger erasure assurance need a qualified native or
 * platform backend with an independently reviewed ownership and fallback policy.
 *
 * @param base64Key - Base64-encoded key material to zero
 *
 * @example
 * ```typescript
 * const messageKey = "dGVzdEtleTE...";
 * secureZero(messageKey);  // Zeroes decoded bytes, original string persists until GC
 * // messageKey should now be deleted from storage
 * ```
 */
export function secureZero(base64Key: Base64 | string): void {
  if (!base64Key) return;

  try {
    // Convert base64 to bytes (asBase64 is a type assertion, safe here)
    const bytes = base64ToBytes(asBase64(base64Key));

    // Overwrite with zeros
    // Note: In JavaScript, we can't guarantee this won't be optimized away,
    // but we make a best effort by:
    // 1. Writing zeros to the Uint8Array
    // 2. Multiple passes to prevent compiler optimization
    for (let pass = 0; pass < 3; pass++) {
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
      }
    }

    // Force a read to prevent dead code elimination
    let sum = 0;
    for (let i = 0; i < bytes.length; i++) {
      sum += bytes[i] ?? 0;
    }

    // Ensure sum is used (prevents optimization)
    if (sum !== 0) {
      // This should never happen, but prevents optimizer from removing zeroing
      console.warn('[SecureZero] Warning: Zeroing may have been optimized away');
    }
  } catch (error) {
    // If zeroing fails, log but don't throw (caller still needs to delete)
    console.error('[SecureZero] Failed to zero key material:', error);
  }
}

/**
 * Best-effort clearing of a Uint8Array in place
 *
 * @param bytes - Byte array to zero
 */
export function secureZeroBytes(bytes: Uint8Array): void {
  if (!bytes || bytes.length === 0) return;

  // Use native fill(0) — harder for JIT to optimize away than a JS loop.
  // Matches noble-hashes' approach (6 security audits).
  // Note: JS provides no guarantee against JIT dead-code elimination.
  bytes.fill(0);

  // Force a read to prevent dead code elimination
  let sum = 0;
  for (let i = 0; i < bytes.length; i++) {
    sum += bytes[i]!;
  }

  if (sum !== 0) {
    console.warn('[SecureZero] Warning: Byte zeroing may have been optimized away');
  }
}
