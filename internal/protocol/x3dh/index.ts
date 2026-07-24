/**
 * X3DH (Extended Triple Diffie-Hellman)
 *
 * @layer 4 - Domain/Algorithms
 *
 * X3DH is the key agreement protocol used in the Signal Protocol to establish
 * shared secrets between two parties. It provides mutual authentication,
 * forward secrecy, and cryptographic deniability.
 *
 * @see https://signal.org/docs/specifications/x3dh/
 */

// Note: Key types (IdentityKeyPair, EcSignedPreKey, etc.) should be imported from keys/

// Core X3DH functions and types
export {};
export { performX3DH, performX3DHResponder, calculateX3DHSharedSecret } from './x3dh';

export type { EphemeralKeyPair, X3DHResult, X3DHResponderResult, X3DHResponderInput } from './x3dh';
