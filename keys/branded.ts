/**
 * Branded Types for Signal Protocol Keys
 *
 * Branded types provide compile-time type safety with zero runtime cost.
 * They prevent accidentally mixing different kinds of base64 strings
 * (public keys, private keys, signatures, etc.).
 *
 * All key types extend Base64 (include the base64 brand), so they can be
 * passed to functions expecting Base64 strings while still maintaining
 * their specific type identity.
 *
 * @example
 * ```typescript
 * const publicKey: PublicKey = "base64string" as PublicKey;
 * const privateKey: PrivateKey = "base64string" as PrivateKey;
 *
 * function verify(key: PublicKey) { }
 * verify(publicKey);  // ✓ OK
 * verify(privateKey); // ✗ Type error!
 *
 * function decode(b64: Base64) { }
 * decode(publicKey);  // ✓ OK - PublicKey extends Base64
 * ```
 */

import type { Base64 } from '../types/utils';

/**
 * Branded type symbols for compile-time type safety.
 */
export {};
declare const __brand_public: unique symbol;
declare const __brand_private: unique symbol;
declare const __brand_signature: unique symbol;
declare const __brand_ciphertext: unique symbol;

/**
 * Base64-encoded public key.
 *
 * Branded type prevents accidentally using a private key where a public key
 * is expected, or vice versa. TypeScript will catch these errors at compile time.
 *
 * Extends Base64, so can be passed to functions expecting Base64.
 */
export type PublicKey = Base64 & { readonly [__brand_public]: true };

/**
 * Base64-encoded private key (stored only in SecureStore).
 *
 * Branded type ensures private keys aren't accidentally passed where
 * public keys are expected.
 *
 * Extends Base64, so can be passed to functions expecting Base64.
 */
export type PrivateKey = Base64 & { readonly [__brand_private]: true };

/**
 * Base64-encoded signature.
 *
 * Branded type prevents mixing signatures with keys or ciphertext.
 *
 * Extends Base64, so can be passed to functions expecting Base64.
 */
export type Signature = Base64 & { readonly [__brand_signature]: true };

/**
 * Base64-encoded ciphertext.
 *
 * Branded type ensures ciphertext isn't confused with keys or signatures.
 *
 * Extends Base64, so can be passed to functions expecting Base64.
 */
export type Ciphertext = Base64 & { readonly [__brand_ciphertext]: true };

/**
 * Generic key pair (public + private).
 *
 * Used for X25519 (ECDH) and Ed25519 (signing) key pairs.
 */
export interface KeyPair {
  publicKey: PublicKey;
  privateKey: PrivateKey;
}
