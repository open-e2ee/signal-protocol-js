/**
 * Double Ratchet DH Ratchet Operations
 *
 * @module double-ratchet/ratchet
 *
 * Implements the Diffie-Hellman ratchet step from the Signal Protocol specification.
 * The DH ratchet rotates the root key and creates new sending/receiving chain keys,
 * providing "break-in recovery" - future messages remain secure even if current
 * state is compromised.
 *
 * ## How the DH Ratchet Works
 *
 * When Alice receives a message with a new DH public key from Bob:
 *
 * 1. Alice stores her current sending chain message count in `PN` (previous N)
 * 2. Alice resets both `Ns` and `Nr` counters to 0
 * 3. Alice updates `DHr` with Bob's new public key
 * 4. Alice computes `DH(DHs, DHr)` to derive new receiving chain key
 * 5. Alice generates a new DH key pair `DHs`
 * 6. Alice computes `DH(DHs, DHr)` to derive new sending chain key
 *
 * ## Security Properties
 *
 * - **Forward secrecy**: Ratchet advancement removes obsolete keys from live state
 * - **Break-in recovery**: An uncompromised DH ratchet step refreshes future keys
 * - **Best-effort cleanup**: Owned key buffers are cleared after use; JavaScript
 *   runtimes do not guarantee physical erasure
 *
 * ## Specification References
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet - DH ratchet algorithm
 * @see https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms - KDF definitions
 * @see https://signal.org/docs/specifications/doubleratchet/#deletion-of-skipped-message-keys - Key deletion policy
 *
 * @example Ratchet step during message processing
 * ```typescript
 * // When receiving a message with new ratchet key
 * if (message.ratchetKey !== state.DHr) {
 *   await performDHRatchetStep(state, message.ratchetKey);
 * }
 * // Then derive message key from receiving chain
 * const { messageKey, newChainKey } = await deriveMessageKey(state.CKr);
 * ```
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../../logger';
import {
  generateECDHKeyPair,
  computeSharedSecret,
  kdfRootKey,
  bytesToBase64,
  base64ToBytes,
  secureZeroBytes,
  X25519_KEY_BYTES,
} from '../../crypto';
import { asBase64, type Base64 } from '../../../types/utils';
import type { ReceiverChain } from '../../../types/session';

// ============================================================================
// Double Ratchet Types
// ============================================================================

/**
 * Double Ratchet key pair (X25519)
 */
export {};
export interface RatchetKeyPair {
  publicKey: Base64;
  privateKey: Base64;
}

/**
 * Message header (all plaintext in Section 3 variant)
 *
 * Field names map directly to SignalProtocolMessage wire fields:
 */
export interface MessageHeader {
  /** Sender's current ratchet public key (proto: ratchet_key, field 1) */
  ratchetKey: Base64;
  /** Message counter in current sending chain (proto: counter, field 2) */
  counter: number;
  /** Number of messages in previous sending chain (proto: previous_counter, field 3) */
  previousCounter: number;
}

/**
 * Double Ratchet session state
 *
 * Per Signal Protocol Section 3.2 - State Variables
 *
 * Note: This uses Section 3 variant (plaintext headers + MAC).
 * Header encryption keys (HKs, HKr, NHKs, NHKr) are not used.
 */
export interface DoubleRatchetState {
  // ============================================
  // DH Ratchet State
  // ============================================

  /** Our current DH key pair (DHs) */
  DHs: RatchetKeyPair;
  /** Their current DH public key (DHr) */
  DHr: Base64;
  /** Current root key (RK) */
  RK: Base64;

  // ============================================
  // Sending Chain State
  // ============================================

  /** Current sending chain key (CKs) */
  CKs: Base64;
  /** Sending message counter (Ns) */
  Ns: number;

  // ============================================
  // Receiving Chain State
  // ============================================

  /** Current receiving chain key (CKr) */
  CKr: Base64;
  /** Receiving message counter (Nr) */
  Nr: number;
  /** Previous sending chain length (PN) */
  PN: number;

  // ============================================
  // Skipped Message Keys (Section 3.5)
  // ============================================

  /**
   * Receiver chains with skipped message keys.
   *
   * Stores up to MAX_RECEIVER_CHAINS (5) chains and their skipped keys.
   */
  receiverChains: ReceiverChain[];

  // ============================================
  // Processed Chains for Replay Detection
  // ============================================

  /**
   * Processed receiving chains for replay detection.
   *
   * When a DH ratchet occurs, we store the old DHr and its final Nr value
   * to detect replay attacks. If a message arrives with an old DHr:
   * - If in receiverChains: decrypt (out-of-order message)
   * - If in processedChains but not receiverChains: replay attack (already processed)
   * - If not in either: new chain (perform DH ratchet)
   *
   * Key: DHr (Base64 DH public key)
   * Value: { lastNr: number, timestamp: number }
   */
  processedChains?: Record<string, { lastNr: number; timestamp: number }>;
}

/**
 * Configuration for Double Ratchet (and Triple Ratchet SPQR)
 */
export interface DoubleRatchetConfig {
  /** Maximum messages to skip in a single chain (DoS protection) */
  maxSkippedMessages: number;
  /** Maximum total message keys to store */
  maxMessageKeysStored: number;
  /** Maximum age of stored message keys (ms) */
  maxMessageKeyAge: number;
  /**
   * Kyber/ML-KEM refresh interval for Triple Ratchet (SPQR)
   *
   * The SPQR announcement describes refreshing post-quantum keys approximately
   * every 50 messages (or within 1 week if chat is inactive).
   *
   * Trade-offs:
   * - Lower interval = better PCS recovery but more bandwidth (~2KB per refresh)
   * - Higher interval = less bandwidth but longer exposure window
   * - The published profile uses 50 messages as the balance point (~40 bytes overhead per message)
   *
   * @see https://signal.org/blog/spqr/ - "approximately every 50 messages"
   */
  kyberRefreshInterval: number;
}

/**
 * Default Double Ratchet configuration
 *
 * | Parameter | Value | Rationale |
 * |-----------|-------|--------|
 * | maxSkippedMessages | 25000 | Bounded forward progress |
 * | maxMessageKeysStored | 2000 | Bounded out-of-order storage |
 * | maxMessageKeyAge | 7 days | Bounded retained key lifetime |
 * | kyberRefreshInterval | 50 | SPQR publication guidance |
 *
 * @see https://signal.org/blog/spqr/
 */
export const DEFAULT_RATCHET_CONFIG: DoubleRatchetConfig = {
  maxSkippedMessages: 25000,
  maxMessageKeysStored: 2000,
  maxMessageKeyAge: 7 * 24 * 60 * 60 * 1000,
  kyberRefreshInterval: 50,
};

// ============================================================================
// Signal Protocol Constants
// ============================================================================

/**
 * Maximum number of receiver chains to store.
 *
 * The reference implementation maintains up to 5 receiver chains for handling out-of-order
 * DH ratchets. When a 6th chain would be added, the oldest is evicted.
 *
 */
export const MAX_RECEIVER_CHAINS = 5;

/**
 * Maximum messages to skip in a single chain (DoS protection).
 *
 */
export const MAX_SKIP = 25000;

/**
 * Maximum total message keys to store across all receiver chains.
 *
 * This is a global limit, not per-chain. When exceeded, oldest keys
 * are evicted using FIFO strategy.
 *
 */
export const MAX_MESSAGE_KEYS = 2000;

/**
 * Result of encrypting a message
 */
export interface EncryptResult {
  /** Message header (all plaintext) */
  header: MessageHeader;
  /** Ciphertext (Base64) */
  ciphertext: Base64;
  /** MAC (Base64) - 8-byte truncated HMAC-SHA256 with identity binding */
  mac: Base64;
}

/**
 * Input for decrypting a message
 *
 * Field names map directly to SignalProtocolMessage wire fields.
 */
export interface DecryptInput {
  /** Sender's current ratchet public key (proto: ratchet_key, field 1) */
  ratchetKey: Base64;
  /** Message counter in current sending chain (proto: counter, field 2) */
  counter: number;
  /** Number of messages in previous sending chain (proto: previous_counter, field 3) */
  previousCounter: number;
  /** Ciphertext */
  ciphertext: Base64;
  /** MAC - 8-byte truncated HMAC-SHA256 */
  mac: Base64;
}

// ============================================================================
// DH Ratchet Operations
// ============================================================================

/**
 * Validate DH public key size
 *
 * Ensures received DH public key is exactly 32 bytes (X25519 requirement).
 * Prevents invalid point attacks and ensures protocol compliance.
 *
 * @param dhPublicKeyB64 Base64-encoded DH public key
 * @throws Error if key size is invalid
 */
function validateDHPublicKey(dhPublicKeyB64: string): void {
  const bytes = base64ToBytes(asBase64(dhPublicKeyB64));
  if (bytes.length !== X25519_KEY_BYTES) {
    throw new Error(
      `Invalid DH public key in message: expected ${X25519_KEY_BYTES} bytes, got ${bytes.length}`
    );
  }
}

/**
 * Perform DH ratchet step when receiving a new DH public key
 *
 * Implements Signal Protocol Section 3.5 DHRatchet.
 * Called when receiving a message with a new DH public key.
 *
 * The ratchet updates the root KDF chain twice:
 * 1. DH(our current DHs, received DHr) → new root key + receiving chain key
 * 2. DH(new DHs, received DHr) → new root key + sending chain key
 *
 * @param state Current ratchet state (mutated in place)
 * @param receivedDHPublicKey Partner's new DH public key (Base64)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
 */
export async function performDHRatchetStep(
  state: DoubleRatchetState,
  receivedDHPublicKey: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<void> {
  // Validate received DH public key before any state changes
  validateDHPublicKey(receivedDHPublicKey);

  logger.breadcrumb('DH ratchet step', {
    category: 'E2EE',
    level: 'debug',
    data: {
      operation: 'ratchet',
      oldDHr: state.DHr?.substring(0, 16),
      newDHr: receivedDHPublicKey.substring(0, 16),
      currentDHs: state.DHs?.publicKey.substring(0, 16),
    },
  });

  // ========================================================================
  // DHRatchet (Signal Protocol Section 3.5)
  // ========================================================================

  // Step 1: Store current sending chain length in PN (previous chain length)
  state.PN = state.Ns;
  state.Ns = 0;
  state.Nr = 0;

  // Step 2: Update DHr with received public key
  state.DHr = asBase64(receivedDHPublicKey);

  // Step 3: DH(DHs, DHr) - compute shared secret with our current key
  const rootKeyBytes = base64ToBytes(state.RK);

  logger.debug('Computing DH1 for receiving chain', {
    category: 'E2EE',
    data: {
      operation: 'ratchet',
      step: 'DH1',
      description: 'DH(our current DHs, received DHr)',
    },
  });

  const dhOutput1 = await computeSharedSecret(state.DHs.privateKey, asBase64(receivedDHPublicKey));

  // Step 4: Derive new root key and receiving chain key
  const { rootKey: newRootKey1, chainKey: newReceivingChainKey } = await kdfRootKey(
    rootKeyBytes,
    dhOutput1
  );

  // Securely zero old root key after deriving new one (Spec 8.1)
  secureZeroBytes(rootKeyBytes);

  state.RK = bytesToBase64(newRootKey1);
  state.CKr = bytesToBase64(newReceivingChainKey);

  // Step 5: Generate new DH key pair for sending
  state.DHs = await generateECDHKeyPair();

  // Step 6: DH(DHs, DHr) - compute shared secret with our new key
  const dhOutput2 = await computeSharedSecret(state.DHs.privateKey, state.DHr);

  // Step 7: Derive new root key and sending chain key
  const { rootKey: newRootKey2, chainKey: newSendingChainKey } = await kdfRootKey(
    newRootKey1,
    dhOutput2
  );

  // Securely zero intermediate root key and DH outputs (Spec 8.1)
  secureZeroBytes(newRootKey1);
  secureZeroBytes(dhOutput1);
  secureZeroBytes(dhOutput2);

  state.RK = bytesToBase64(newRootKey2);
  state.CKs = bytesToBase64(newSendingChainKey);

  // Securely zero derived chain keys after storing (Spec 8.1)
  secureZeroBytes(newReceivingChainKey);
  secureZeroBytes(newSendingChainKey);

  logger.debug('DH ratchet step complete', {
    category: 'E2EE',
    data: {
      operation: 'ratchet',
      newDHsPub: state.DHs.publicKey.substring(0, 16),
    },
  });
}

/**
 * Check if a received DH public key triggers a ratchet step
 *
 * A ratchet step is needed when the received DH public key is different
 * from our current DHr (partner's last known DH key).
 *
 * @param state Current ratchet state
 * @param receivedDHPublicKey Partner's DH public key from message
 * @returns true if ratchet step is needed
 */
export function needsDHRatchet(state: DoubleRatchetState, receivedDHPublicKey: string): boolean {
  return state.DHr !== receivedDHPublicKey;
}
