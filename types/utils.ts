/**
 * Utility type definitions with branded types for compile-time safety
 *
 * Base64, Hex, and Bytes are now fully branded types that require explicit
 * conversion via asBase64(), asHex(), and asBytes() functions.
 *
 * This prevents accidental mixing of different string encodings and provides
 * compile-time type safety throughout the Signal Protocol implementation.
 *
 * @example
 * ```typescript
 * import { Base64, asBase64 } from './utils';
 *
 * // Explicit conversion required
 * const key: Base64 = asBase64('SGVsbG8gV29ybGQ=');
 *
 * // Plain strings are NOT assignable to Base64
 * // const wrong: Base64 = 'plain string'; // Error!
 *
 * // Validated conversion with runtime check
 * const validated = toBase64('SGVsbG8gV29ybGQ='); // throws if invalid
 * ```
 */

// ============================================================================
// Brand Symbols (unique to prevent structural compatibility)
// ============================================================================
export {};
declare const __brand_base64: unique symbol;
declare const __brand_hex: unique symbol;
declare const __brand_bytes: unique symbol;

// ============================================================================
// Branded Types (enforced type safety)
// ============================================================================

/**
 * Base64-encoded string (branded type)
 *
 * Prevents accidental mixing of Base64 with plain strings.
 * Requires explicit conversion via `asBase64()`.
 */
export type Base64 = string & { readonly [__brand_base64]: true };

/**
 * Hexadecimal-encoded string (branded type)
 *
 * Prevents accidental mixing of Hex with plain strings.
 * Requires explicit conversion via `asHex()`.
 */
export type Hex = string & { readonly [__brand_hex]: true };

/**
 * Raw bytes as Uint8Array (branded type)
 *
 * Prevents accidental mixing of Bytes with plain Uint8Array.
 * Requires explicit conversion via `asBytes()`.
 */
export type Bytes = Uint8Array & { readonly [__brand_bytes]: true };

// ============================================================================
// Constructor Functions (type assertions)
// ============================================================================

/**
 * Convert a string to Base64 type (type assertion)
 *
 * This does NOT validate the input - use `toBase64()` for validated conversion.
 */
export function asBase64(value: string): Base64 {
  return value as Base64;
}

/**
 * Convert a string to Hex type (type assertion)
 *
 * This does NOT validate the input - use `toHex()` for validated conversion.
 */
export function asHex(value: string): Hex {
  return value as Hex;
}

/**
 * Convert a Uint8Array to Bytes type (type assertion)
 */
export function asBytes(value: Uint8Array): Bytes {
  return value as Bytes;
}

// ============================================================================
// Type Guards (for runtime validation)
// ============================================================================

/**
 * Check if a string is valid Base64
 *
 * Note: This only checks format, not semantic validity.
 */
export function isValidBase64(value: string): boolean {
  // Standard Base64 regex (allows padding)
  return /^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.length % 4 === 0;
}

/**
 * Check if a string is valid hexadecimal
 */
export function isValidHex(value: string): boolean {
  return /^[0-9a-fA-F]*$/.test(value) && value.length % 2 === 0;
}

/**
 * Safely convert a string to Base64, with validation
 *
 * @throws Error if the string is not valid Base64
 */
export function toBase64(value: string): Base64 {
  if (!isValidBase64(value)) {
    throw new Error(`Invalid Base64 string: ${value.slice(0, 20)}...`);
  }
  return value as Base64;
}

/**
 * Safely convert a string to Hex, with validation
 *
 * @throws Error if the string is not valid hexadecimal
 */
export function toHex(value: string): Hex {
  if (!isValidHex(value)) {
    throw new Error(`Invalid hexadecimal string: ${value.slice(0, 20)}...`);
  }
  return value as Hex;
}
