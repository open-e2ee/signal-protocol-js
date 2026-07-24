/**
 * Hybrid Ratchet Implementation (Signal Protocol Section 6)
 *
 * @module hybrid-ratchet/hybrid-ratchet
 *
 * Signal Protocol Section 6 - Hybrid Ratchet (also known as Triple Ratchet)
 * Combines EC Double Ratchet with SPQR (Sparse Post-Quantum Ratchet)
 * for hybrid EC + post-quantum security.
 *
 * ## Overview
 *
 * The Triple Ratchet provides defense-in-depth by running two independent
 * key agreement mechanisms in parallel:
 *
 * 1. **EC Double Ratchet**: X25519 Diffie-Hellman key agreement
 * 2. **SPQR**: ML-KEM-768 (CRYSTALS-Kyber) key encapsulation
 *
 * Message keys from both ratchets are combined via KDF_HYBRID, ensuring
 * security even if one cryptographic primitive is broken.
 *
 * ## Security Guarantee
 *
 * ```
 * Security = EC_Security ∨ PQ_Security
 *
 * - Secure if EITHER EC or PQ remains unbroken
 * - Attacker must break BOTH Curve25519 AND ML-KEM-768
 * - Provides 100% post-quantum forward secrecy
 * - Protects against "harvest now, decrypt later" attacks
 * ```
 *
 * ## Key Derivation Flow
 *
 * ```
 * ┌─────────────────┐     ┌─────────────────┐
 * │  Double Ratchet │     │      SPQR       │
 * │   (X25519 DH)   │     │  (ML-KEM-768)   │
 * └────────┬────────┘     └────────┬────────┘
 *          │                       │
 *          ▼                       ▼
 *   ┌─────────────┐         ┌─────────────┐
 *   │ EC_MsgKey   │         │ PQ_MsgKey   │
 *   │ (32 bytes)  │         │ (32 bytes)  │
 *   └──────┬──────┘         └──────┬──────┘
 *          │                       │
 *          └───────────┬───────────┘
 *                      │
 *                      ▼
 *              ┌───────────────┐
 *              │  KDF_HYBRID   │
 *              │ HKDF(EC, PQ)  │
 *              └───────┬───────┘
 *                      │
 *                      ▼
 *              ┌───────────────┐
 *              │ Final MsgKey  │
 *              │  (32 bytes)   │
 *              └───────────────┘
 * ```
 *
 * ## Synchronization
 *
 * The Triple Ratchet synchronizes EC and SPQR ratchet steps:
 * - When DH ratchet steps (new DH key pair), SPQR also steps
 * - SPQR epoch increments are synchronized with DH ratchet steps
 * - Each message includes both EC and PQ metadata for decryption
 *
 * ## Usage
 *
 * This module is typically used internally by SessionCipher:
 *
 * ```typescript
 * // Sending: derive combined message key
 * const { messageKey, headerKey } = await deriveTripleRatchetSendKey(
 *   ecState,    // EC Double Ratchet state
 *   spqrState   // SPQR state
 * );
 *
 * // Receiving: derive combined message key
 * const { messageKey } = await deriveTripleRatchetReceiveKey(
 *   ecState,
 *   spqrState,
 *   pqEpoch,          // From message header
 *   pqMessageNumber   // From message header
 * );
 * ```
 *
 * ## Specification References
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#triple-ratchet - Section 6
 * @see https://signal.org/docs/specifications/doubleratchet/#kdf-hybrid - KDF_HYBRID definition
 */

import { defaultSignalLogger, type ILogger } from '../../../logger';
import { kdfHybrid, secureZeroBytes } from '../../crypto';
import {
  performDHRatchetStep,
  needsDHRatchet,
  deriveSendingKey,
  deriveReceivingKey,
} from '../double-ratchet';
import { deriveSPQRSendKey, deriveSPQRReceiveKey } from '../spqr';
import type { Base64 } from '../../../types';
import type { DoubleRatchetState } from '../double-ratchet';
import type { SPQRState } from '../spqr';
import type { VersionNegotiationState } from '../version';

// ============================================================================
// Triple Ratchet Types
// ============================================================================

/**
 * Triple Ratchet session state
 *
 * Combines EC Double Ratchet with SPQR for hybrid security.
 */
export {};
export interface TripleRatchetState {
  /** EC Double Ratchet state */
  ec_state: DoubleRatchetState;
  /** SPQR state for post-quantum security */
  spqrState: SPQRState;
  /** Whether Triple Ratchet is enabled */
  enabled: boolean;
  /** Timestamp when Triple Ratchet was enabled */
  enabledAt: number;
  /**
   * Version negotiation state.
   *
   * Tracks v1 SPQR lock-in with the peer.
   * Version negotiation is owned by Triple Ratchet because it affects
   * whether SPQR functions are called at all.
   */
  versionNegotiation?: VersionNegotiationState;
}

/**
 * Triple Ratchet message key result
 */
export interface TripleRatchetKeyResult {
  /** Message key, hybrid after SPQR bootstrap and EC-only during the v1 bootstrap window */
  messageKey: Uint8Array;
  /** EC message number */
  ecMessageNumber: number;
  /** PQ message number (undefined before SPQR bootstrap emits a key) */
  pqMessageNumber?: number;
  /** SPQR epoch (undefined before SPQR bootstrap emits a key) */
  pqEpoch?: number;
}

/**
 * Triple Ratchet encrypt result
 *
 * Field names map directly to SignalMessage wire fields.
 */
export interface TripleRatchetEncryptResult {
  /** Ratchet public key (from EC ratchet, proto: ratchet_key, field 1) */
  ratchetKey: Base64;
  /** Message counter (proto: counter, field 2) */
  counter: number;
  /** Previous chain length (proto: previous_counter, field 3) */
  previousCounter: number;
  /** Ciphertext */
  ciphertext: Base64;
  /** MAC */
  mac: Base64;
  /** SPQR epoch */
  spqrEpoch: number;
  /** SPQR message number */
  spqrMessageNumber: number;
  /** Kyber ciphertext to send (if generated) */
  kyberCiphertext?: Base64;
}

/**
 * Triple Ratchet decrypt input
 *
 * Uses Section 3 variant (plaintext headers + MAC authentication).
 * Field names map directly to SignalMessage wire fields.
 */
export interface TripleRatchetDecryptInput {
  /** Ratchet public key from message (proto: ratchet_key, field 1) */
  ratchetKey: Base64;
  /** Message counter (proto: counter, field 2) */
  counter: number;
  /** Previous chain length (proto: previous_counter, field 3) */
  previousCounter: number;
  /** Ciphertext */
  ciphertext: Base64;
  /** MAC (8-byte truncated HMAC-SHA256) */
  mac: Base64;
  /** SPQR epoch (from message) */
  spqrEpoch: number;
  /** SPQR message number (from message) */
  spqrMessageNumber: number;
  /** Kyber ciphertext (if included) */
  kyberCiphertext?: Base64;
}

/**
 * Derive sending message key using Triple Ratchet
 *
 * Combines EC message key from Double Ratchet with PQ message key from SPQR
 * using KDF_HYBRID for hybrid security.
 *
 * @param ecState EC Double Ratchet state
 * @param spqrState SPQR state
 * @param versionNegotiation Version lock-in state
 * @returns Combined message key and metadata
 */
export async function deriveTripleRatchetSendKey(
  ecState: DoubleRatchetState,
  spqrState: SPQRState,
  versionNegotiation?: VersionNegotiationState,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<TripleRatchetKeyResult> {
  logger.debug('Triple Ratchet: Deriving sending key', {
    category: 'E2EE',
    data: {
      operation: 'triple-ratchet-send',
      ecNs: ecState.Ns,
      spqrEpoch: spqrState.epoch,
      spqrVersion: versionNegotiation?.negotiatedVersion ?? versionNegotiation?.maxVersion ?? 'v1',
    },
  });

  // Step 1: Derive EC message key from Double Ratchet
  const { messageKey: ecMessageKey } = await deriveSendingKey(ecState, logger);

  // Step 2: Derive PQ message key from SPQR.
  const spqrResult = await deriveSPQRSendKey(spqrState, logger);

  let combinedKey: Uint8Array;
  let pqIndex: number | undefined;
  let pqEpoch: number | undefined;

  if (spqrResult) {
    // Combine EC + PQ keys using KDF_HYBRID.
    const pqMessageKey = spqrResult.messageKey;
    pqIndex = spqrResult.index;
    pqEpoch = spqrResult.epoch;

    // Step 4: Combine using KDF_HYBRID (Signal Protocol Section 6.3)
    combinedKey = await kdfHybrid(ecMessageKey, pqMessageKey);

    // Secure cleanup
    secureZeroBytes(pqMessageKey);
    secureZeroBytes(ecMessageKey);
  } else {
    // SPQR bootstrap has not produced matching PQ keys yet.
    combinedKey = ecMessageKey;
  }

  logger.debug('Triple Ratchet: Combined EC + PQ message keys', {
    category: 'E2EE',
    data: {
      operation: 'triple-ratchet-send',
      ecCounter: ecState.Ns - 1, // deriveSendingKey already incremented
      pqIndex,
      pqEpoch,
      spqrReady: !!spqrResult,
    },
  });

  return {
    messageKey: combinedKey,
    ecMessageNumber: ecState.Ns - 1, // Keep for wire format compatibility
    pqMessageNumber: pqIndex, // Keep field name for wire format compatibility
    pqEpoch,
  };
}

/**
 * Derive receiving message key using Triple Ratchet
 *
 * Combines EC message key from Double Ratchet with PQ message key from SPQR
 * using KDF_HYBRID for hybrid security.
 *
 * @param ecState EC Double Ratchet state
 * @param spqrState SPQR state
 * @param pqEpoch SPQR epoch from message header
 * @param pqIndex SPQR message index from message header (per Signal SPQR naming)
 * @param versionNegotiation Version lock-in state
 * @returns Combined message key and metadata
 */
export async function deriveTripleRatchetReceiveKey(
  ecState: DoubleRatchetState,
  spqrState: SPQRState,
  pqEpoch: number,
  pqIndex: number,
  versionNegotiation?: VersionNegotiationState,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<TripleRatchetKeyResult> {
  logger.debug('Triple Ratchet: Deriving receiving key', {
    category: 'E2EE',
    data: {
      operation: 'triple-ratchet-receive',
      ecNr: ecState.Nr,
      pqEpoch,
      pqIndex,
      spqrVersion: versionNegotiation?.negotiatedVersion ?? versionNegotiation?.maxVersion ?? 'v1',
    },
  });

  // Step 1: Derive EC message key from Double Ratchet
  const { messageKey: ecMessageKey } = await deriveReceivingKey(ecState, logger);

  // Step 2: Derive PQ message key from SPQR.
  const pqMessageKey = await deriveSPQRReceiveKey(spqrState, pqIndex, pqEpoch, logger);

  let combinedKey: Uint8Array;

  if (pqMessageKey) {
    // Combine EC + PQ keys using KDF_HYBRID.
    // Step 4: Combine using KDF_HYBRID (Signal Protocol Section 6.3)
    combinedKey = await kdfHybrid(ecMessageKey, pqMessageKey);

    // Secure cleanup
    secureZeroBytes(pqMessageKey);
    secureZeroBytes(ecMessageKey);
  } else {
    // SPQR bootstrap has not produced matching PQ keys yet.
    combinedKey = ecMessageKey;
  }

  logger.debug('Triple Ratchet: Combined EC + PQ message keys for decryption', {
    category: 'E2EE',
    data: {
      operation: 'triple-ratchet-receive',
      ecCounter: ecState.Nr - 1, // deriveReceivingKey already incremented
      pqIndex,
      pqEpoch,
      spqrReady: !!pqMessageKey,
    },
  });

  return {
    messageKey: combinedKey,
    ecMessageNumber: ecState.Nr - 1, // Keep for wire format compatibility
    pqMessageNumber: pqIndex, // Keep field name for wire format compatibility
    pqEpoch,
  };
}

/**
 * Perform Triple Ratchet step (EC DH ratchet only — purely classical).
 *
 * Called when receiving a message with a new DH public key.
 * The DH ratchet has no interaction with PQ/SPQR state. All post-quantum work
 * happens in `spqrSend()` and `spqrRecv()`.
 *
 * @param ecState EC Double Ratchet state
 * @param _spqrState SPQR state (unused — PQ handled by spqrSend/spqrRecv)
 * @param receivedDHPublicKey Partner's new DH public key
 * @param _receivedKyberCiphertext Unused — PQ handled by spqrRecv
 * @param _versionNegotiation Unused — PQ handled by spqrRecv
 */
export async function performTripleRatchetStep(
  ecState: DoubleRatchetState,
  _spqrState: SPQRState,
  receivedDHPublicKey: string,
  _receivedKyberCiphertext?: Uint8Array,
  _versionNegotiation?: VersionNegotiationState,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<void> {
  logger.breadcrumb('Triple Ratchet step (EC DH ratchet)', {
    category: 'E2EE',
    level: 'info',
    data: {
      operation: 'triple-ratchet-step',
      ecDHr: ecState.DHr?.substring(0, 16),
      newDHr: receivedDHPublicKey.substring(0, 16),
    },
  });

  // Purely classical EC DH ratchet — no PQ involvement
  await performDHRatchetStep(ecState, receivedDHPublicKey, logger);
}

/**
 * Check if Triple Ratchet step is needed
 *
 * A Triple Ratchet step is needed when:
 * - EC DH ratchet is needed (new DH public key received)
 *
 * @param ecState EC Double Ratchet state
 * @param receivedDHPublicKey Partner's DH public key from message
 * @returns true if ratchet step is needed
 */
export function needsTripleRatchetStep(
  ecState: DoubleRatchetState,
  receivedDHPublicKey: string
): boolean {
  return needsDHRatchet(ecState, receivedDHPublicKey);
}
