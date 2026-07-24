/**
 * PQXDH (Post-Quantum Extended Diffie-Hellman)
 *
 * @layer 4 - Domain/Algorithms
 *
 * This package extends its X3DH-derived key agreement with standardized
 * ML-KEM-1024 for a hybrid post-quantum contribution.
 *
 * Its hybrid guarantees are conditional on identity authentication, KDF and
 * transcript binding, uncompromised entropy/state, and at least one component
 * assumption remaining secure. See docs/SECURITY.md.
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

// Core PQXDH functions
export {};
export { performPQXDH, performPQXDHResponder } from './pqxdh';

// Key types (re-exported from keys/ for convenience)
export type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  PreKeyBundle,
  KeyPair,
} from './pqxdh';

// Protocol-specific types
export type {
  EphemeralKeyPair,
  PQXDHResult,
  PQXDHResponderResult,
  PQXDHResponderInput,
} from './pqxdh';
