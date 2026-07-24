/**
 * Triple Ratchet - Layer 4 Submodule: Combined EC + PQ Ratcheting
 *
 * Signal Protocol Section 6 - Triple Ratchet
 * Combines EC Double Ratchet with SPQR (Sparse Post-Quantum Ratchet)
 * for hybrid EC + post-quantum security.
 *
 * The name "Triple Ratchet" describes the architecture:
 * - Ratchet 1: Classical DH ratchet (X25519)
 * - Ratchet 2: Symmetric ratchet (KDF chains)
 * - Ratchet 3: Post-quantum ratchet (SPQR with ML-KEM-768)
 *
 * @see Signal Protocol Section 6
 * @see https://signal.org/blog/pqxdh/ - Triple Ratchet announcement
 */

// Core Triple Ratchet functions
export {};
export {
  deriveTripleRatchetSendKey,
  deriveTripleRatchetReceiveKey,
  performTripleRatchetStep,
  needsTripleRatchetStep,
} from './ratchet';

// Types
export type {
  TripleRatchetState,
  TripleRatchetKeyResult,
  TripleRatchetEncryptResult,
  TripleRatchetDecryptInput,
} from './ratchet';

// Version Negotiation (v1-only SPQR lock-in)
export {
  initVersionNegotiation,
  processVersionCapability,
  isVersionNegotiationComplete,
  getNegotiatedVersion,
  processVersionFromByte,
  serializeVersionNegotiation,
  deserializeVersionNegotiation,
} from '../version';

export type {
  SPQRVersion,
  VersionNegotiationState,
  VersionCapability,
  VersionNegotiationStateJSON,
} from '../version';
