/**
 * Branded Types for Signal Protocol Keys
 *
 * Branded types provide compile-time type safety with zero runtime cost.
 * They prevent accidentally mixing different kinds of base64 strings
 * (public keys, private keys, signatures, etc.).
 *
 * Every key type extends Base64 and includes the base64 brand. A function that
 * expects a Base64 string accepts them, and each one keeps its specific type
 * identity.
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
 * Branded type prevents accidentally using a private key where the API needs a
 * public key, or vice versa. TypeScript catches these errors at compile time.
 *
 * Extends Base64, so a function that expects Base64 accepts it.
 */
export type PublicKey = Base64 & { readonly [__brand_public]: true };

/**
 * Base64-encoded private key (stored only in SecureStore).
 *
 * Branded type prevents a private key from reaching a parameter that needs a
 * public key.
 *
 * Extends Base64, so a function that expects Base64 accepts it.
 */
export type PrivateKey = Base64 & { readonly [__brand_private]: true };

/**
 * Base64-encoded signature.
 *
 * Branded type prevents mixing signatures with keys or ciphertext.
 *
 * Extends Base64, so a function that expects Base64 accepts it.
 */
export type Signature = Base64 & { readonly [__brand_signature]: true };

/**
 * Base64-encoded ciphertext.
 *
 * Branded type keeps ciphertext distinct from keys and signatures.
 *
 * Extends Base64, so a function that expects Base64 accepts it.
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
