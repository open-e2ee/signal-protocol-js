/**
 * Double Ratchet Algorithm - Layer 3: Ratcheting (Classical)
 *
 * The Double Ratchet algorithm combines the DH ratchet and the symmetric-key ratchet
 * to provide forward secrecy and break-in recovery for message encryption.
 *
 * Key features:
 * - Forward secrecy: Past messages remain secure if current keys are compromised
 * - Break-in recovery: Future messages become secure after key rotation
 * - Out-of-order message handling: Skipped message keys are stored for later
 * - Identity-bound MAC: Message authentication with sender/receiver identity binding
 *
 * @see https://signal.org/docs/specifications/doubleratchet/
 */

// DH Ratchet operations
export {};
export { needsDHRatchet, performDHRatchetStep } from './ratchet';

// Chain key operations
export {
  cleanupExpiredKeys,
  deriveReceivingKey,
  deriveSendingKey,
  storeSkippedKeys,
  tryGetSkippedKey,
  // Receiver chain management (v3 protobuf-compatible)
  getOrCreateReceiverChain,
  countTotalMessageKeys,
  evictOldestMessageKey,
  storeMessageKeyInChain,
  consumeMessageKeyFromChain,
} from './chains';

// Types
export type {
  DecryptInput,
  DoubleRatchetConfig,
  DoubleRatchetState,
  EncryptResult,
  MessageHeader,
  RatchetKeyPair,
} from './ratchet';

export { DEFAULT_RATCHET_CONFIG, MAX_RECEIVER_CHAINS, MAX_SKIP, MAX_MESSAGE_KEYS } from './ratchet';
