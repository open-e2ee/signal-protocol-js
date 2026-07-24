/**
 * Signal Protocol Key Type Prefix
 *
 * Signal uses 0x05 (DJB = Daniel J. Bernstein / Curve25519) as a type identifier
 * in serialized keys. Internal storage uses raw 32-byte keys; the prefix is added
 * only for wire format and safety number computation.
 *
 * Architecture:
 * - Storage: 32 bytes (raw key only)
 * - Wire/Safety: 33 bytes (0x05 + 32-byte key)
 *
 */

// ============================================================================
// Constants
// ============================================================================

/**
 * DJB (Curve25519) key type prefix.
 *
 * X25519 public keys in this wire format use the 0x05 DJB key-type prefix.
 */
export {};
export const DJB_KEY_TYPE = 0x05;

/**
 * Raw X25519 public key length (internal storage format).
 */
export const X25519_RAW_KEY_BYTES = 32;

/**
 * Serialized X25519 public key length (wire format: 0x05 + key).
 */
export const X25519_SERIALIZED_KEY_BYTES = 33;

// ============================================================================
// Serialization Functions
// ============================================================================

/**
 * Add 0x05 DJB prefix for wire serialization (32 → 33 bytes).
 *
 * Wire layout:
 * ```text
 * 0x05 || raw_x25519_public_key
 * ```
 *
 * @param rawKey - Raw 32-byte X25519 public key
 * @returns 33-byte serialized key with 0x05 prefix
 * @throws Error if rawKey is not 32 bytes
 */
export function serializePublicKey(rawKey: Uint8Array): Uint8Array {
  if (rawKey.length !== X25519_RAW_KEY_BYTES) {
    throw new Error(
      `Cannot serialize: expected ${X25519_RAW_KEY_BYTES}-byte raw key, got ${rawKey.length}`
    );
  }

  const serialized = new Uint8Array(X25519_SERIALIZED_KEY_BYTES);
  serialized[0] = DJB_KEY_TYPE;
  serialized.set(rawKey, 1);

  return serialized;
}

/**
 * Strip 0x05 DJB prefix after deserialization (33 → 32 bytes).
 *
 * @param serialized - 33-byte serialized key with 0x05 prefix
 * @returns Raw 32-byte X25519 public key
 * @throws Error if serialized is not 33 bytes or has wrong prefix
 */
export function deserializePublicKey(serialized: Uint8Array): Uint8Array {
  if (serialized.length !== X25519_SERIALIZED_KEY_BYTES) {
    throw new Error(
      `Cannot deserialize: expected ${X25519_SERIALIZED_KEY_BYTES}-byte serialized key, got ${serialized.length}`
    );
  }

  if (serialized[0] !== DJB_KEY_TYPE) {
    throw new Error(
      `Invalid key type prefix: expected 0x${DJB_KEY_TYPE.toString(16).padStart(2, '0')}, got 0x${(serialized[0] ?? 0).toString(16).padStart(2, '0')}`
    );
  }

  return serialized.slice(1);
}

/**
 * Check if a key has the 0x05 DJB prefix (is in serialized format).
 *
 * Useful for handling keys that may be in either format.
 *
 * @param key - Key bytes to check
 * @returns true if key is 33 bytes with 0x05 prefix
 */
export function isSerializedPublicKey(key: Uint8Array): boolean {
  return key.length === X25519_SERIALIZED_KEY_BYTES && key[0] === DJB_KEY_TYPE;
}

/**
 * Ensure a key is in serialized format (33 bytes with 0x05 prefix).
 *
 * Accepts both formats:
 * - 32-byte raw key: adds prefix
 * - 33-byte serialized key: validates and returns as-is
 *
 * @param key - Key bytes (32 or 33 bytes)
 * @returns 33-byte serialized key
 * @throws Error if key is not 32 or 33 bytes, or 33 bytes with wrong prefix
 */
export function ensureSerializedPublicKey(key: Uint8Array): Uint8Array {
  if (key.length === X25519_RAW_KEY_BYTES) {
    return serializePublicKey(key);
  }

  if (key.length === X25519_SERIALIZED_KEY_BYTES) {
    if (key[0] !== DJB_KEY_TYPE) {
      throw new Error(
        `Invalid key type prefix: expected 0x${DJB_KEY_TYPE.toString(16).padStart(2, '0')}, got 0x${(key[0] ?? 0).toString(16).padStart(2, '0')}`
      );
    }
    return key;
  }

  throw new Error(
    `Invalid key length: expected ${X25519_RAW_KEY_BYTES} or ${X25519_SERIALIZED_KEY_BYTES} bytes, got ${key.length}`
  );
}

/**
 * Ensure a key is in raw format (32 bytes, no prefix).
 *
 * Accepts both formats:
 * - 32-byte raw key: returns as-is
 * - 33-byte serialized key: validates and strips prefix
 *
 * @param key - Key bytes (32 or 33 bytes)
 * @returns 32-byte raw key
 * @throws Error if key is not 32 or 33 bytes, or 33 bytes with wrong prefix
 */
export function ensureRawPublicKey(key: Uint8Array): Uint8Array {
  if (key.length === X25519_RAW_KEY_BYTES) {
    return key;
  }

  if (key.length === X25519_SERIALIZED_KEY_BYTES) {
    return deserializePublicKey(key);
  }

  throw new Error(
    `Invalid key length: expected ${X25519_RAW_KEY_BYTES} or ${X25519_SERIALIZED_KEY_BYTES} bytes, got ${key.length}`
  );
}
