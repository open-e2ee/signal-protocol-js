/**
 * Double Ratchet Chain Key Operations
 *
 * Implements the symmetric ratchet (chain key derivation) for the Double Ratchet.
 * Each message advances the chain key forward, providing forward secrecy.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 * @see https://signal.org/docs/specifications/doubleratchet/#the-kdf-chains
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../../logger';
import {
  kdfChainKey,
  bytesToBase64,
  base64ToBytes,
  secureZero,
  secureZeroBytes,
} from '../../crypto';
import type { Base64 } from '../../../types';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import type { DoubleRatchetState, DoubleRatchetConfig } from './ratchet';
import { DEFAULT_RATCHET_CONFIG, MAX_RECEIVER_CHAINS, MAX_MESSAGE_KEYS } from './ratchet';
import type { ReceiverChain } from '../../../types/session';

/**
 * Maximum safe message counter value.
 * Beyond this, JavaScript number precision is not guaranteed.
 */
export {};
const MAX_MESSAGE_COUNTER = Number.MAX_SAFE_INTEGER - 1;

/**
 * Derive sending message key and advance sending chain
 *
 * Implements Signal Protocol Section 3.4 - RatchetEncrypt (chain key step).
 * Advances the sending chain and returns the message key for encryption.
 *
 * @param state Current ratchet state
 * @returns Message key for this message
 */
export async function deriveSendingKey(
  state: DoubleRatchetState,
  _logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<{ messageKey: Uint8Array }> {
  // Check for counter overflow before incrementing
  if (state.Ns >= MAX_MESSAGE_COUNTER) {
    throw new EncryptionError(
      'Sending message counter overflow - session must be rotated',
      EncryptionErrorCode.COUNTER_OVERFLOW,
      { operation: 'deriveSendingKey' }
    );
  }

  const chainKeyBytes = base64ToBytes(state.CKs);

  // Guard: empty or invalid chain key would produce deterministic, publicly-computable message keys
  if (chainKeyBytes.length !== 32) {
    throw new EncryptionError(
      'Cannot encrypt: sending chain key not initialized (expected 32 bytes)',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'deriveSendingKey', keyLength: chainKeyBytes.length }
    );
  }

  // KDF_CK: Derive message key and new chain key
  const { chainKey: newChainKey, messageKey } = kdfChainKey(chainKeyBytes);

  // Update state with new chain key
  state.CKs = bytesToBase64(newChainKey);

  // Advance message counter
  state.Ns++;

  // Secure cleanup
  secureZeroBytes(chainKeyBytes);
  secureZeroBytes(newChainKey);

  return { messageKey };
}

/**
 * Derive receiving message key and advance receiving chain
 *
 * Implements Signal Protocol Section 3.4 - RatchetDecrypt (chain key step).
 * Advances the receiving chain and returns the message key for decryption.
 *
 * @param state Current ratchet state
 * @returns Message key for this message
 */
export async function deriveReceivingKey(
  state: DoubleRatchetState,
  _logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<{ messageKey: Uint8Array }> {
  // Check for counter overflow before incrementing
  if (state.Nr >= MAX_MESSAGE_COUNTER) {
    throw new EncryptionError(
      'Receiving message counter overflow - session must be rotated',
      EncryptionErrorCode.COUNTER_OVERFLOW,
      { operation: 'deriveReceivingKey' }
    );
  }

  const chainKeyBytes = base64ToBytes(state.CKr);

  // Guard: empty or invalid chain key would produce deterministic, publicly-computable message keys
  if (chainKeyBytes.length !== 32) {
    throw new EncryptionError(
      'Cannot decrypt: receiving chain key not initialized (expected 32 bytes)',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'deriveReceivingKey', keyLength: chainKeyBytes.length }
    );
  }

  // KDF_CK: Derive message key and new chain key
  const { chainKey: newChainKey, messageKey } = kdfChainKey(chainKeyBytes);

  // Update state with new chain key
  state.CKr = bytesToBase64(newChainKey);

  // Advance message counter
  state.Nr++;

  // Secure cleanup
  secureZeroBytes(chainKeyBytes);
  secureZeroBytes(newChainKey);

  return { messageKey };
}

/**
 * Store skipped message keys when advancing receiving chain
 *
 * If we receive message N+5 but haven't received N+1 through N+4,
 * we need to store the keys for those missing messages so we can
 * decrypt them if they arrive later (out-of-order delivery).
 *
 * Uses the nested receiverChains structure (v3 format) for protobuf compatibility.
 *
 * @param state Current ratchet state
 * @param untilCounter Counter value to advance to (per the reference wire.proto naming)
 * @param config Double Ratchet configuration
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#out-of-order-messages
 */
export async function storeSkippedKeys(
  state: DoubleRatchetState,
  untilCounter: number,
  config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<void> {
  // Replay detection: if counter is less than current Nr, this is a replay
  // of an already-processed message. Throw MESSAGE_DUPLICATE error.
  if (untilCounter < state.Nr) {
    logger.warn('Message replay detected: counter already processed', {
      category: 'E2EE',
      data: {
        operation: 'replay-detected',
        counter: untilCounter,
        currentNr: state.Nr,
      },
    });
    throw new EncryptionError(
      'Message authentication failed',
      EncryptionErrorCode.MESSAGE_DUPLICATE,
      { counter: untilCounter, currentNr: state.Nr }
    );
  }

  // DoS protection: prevent attackers from forcing us to skip too many messages
  if (state.Nr + config.maxSkippedMessages < untilCounter) {
    throw new Error(
      `Too many skipped messages (gap of ${untilCounter - state.Nr} exceeds limit of ${config.maxSkippedMessages})`
    );
  }

  // Ensure receiverChains exists (v3 format)
  if (!state.receiverChains) {
    state.receiverChains = [];
  }

  const chainKeyBytes = base64ToBytes(state.CKr);
  let currentChainKey = chainKeyBytes;

  // Derive and store keys for counters Nr through untilCounter-1
  // Use nested receiverChains structure (v3 format)
  const senderRatchetKey = state.DHr;

  for (let i = state.Nr; i < untilCounter; i++) {
    const { chainKey: newChainKey, messageKey } = kdfChainKey(currentChainKey);

    // Store in nested receiverChains structure (v3 protobuf-compatible)
    storeMessageKeyInChain(state, senderRatchetKey, i, messageKey, config, logger);

    // Secure cleanup: zero intermediates after use (matches cipher.ts skip loop pattern)
    secureZeroBytes(messageKey);
    secureZeroBytes(currentChainKey);
    currentChainKey = newChainKey;
  }

  // Update state
  state.CKr = bytesToBase64(currentChainKey);
  state.Nr = untilCounter;

  // Secure cleanup
  secureZeroBytes(currentChainKey);
  secureZeroBytes(chainKeyBytes);
}

/**
 * Try to retrieve a skipped message key
 *
 * Checks the receiverChains structure for stored message keys.
 *
 * @param state Current ratchet state
 * @param ratchetKey Sender's ratchet public key from message
 * @param counter Message counter
 * @returns Message key if found, null otherwise
 */
export function tryGetSkippedKey(
  state: DoubleRatchetState,
  ratchetKey: Base64,
  counter: number,
  _logger: Required<ILogger> = defaultSignalProtocolLogger
): Uint8Array | null {
  return consumeMessageKeyFromChain(state, ratchetKey, counter);
}

/**
 * Clean up expired message keys from receiverChains
 *
 * Signal Protocol Section 8.4 -
 * "To avoid excessive storage, parties SHOULD delete keys for messages
 * that have been received or that have been skipped for too long.
 * A recommended policy is to delete message keys more than one week old."
 *
 * Also cleans up expired entries from processedChains (replay detection).
 *
 * @param state Session state to clean
 * @param config Double Ratchet configuration with maxMessageKeyAge
 */
export function cleanupExpiredKeys(
  state: DoubleRatchetState,
  config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): void {
  const now = Date.now();
  const expirationTime = now - config.maxMessageKeyAge;

  // ========================================================================
  // Clean up expired processedChains entries (replay detection)
  // ========================================================================
  if (state.processedChains) {
    const chainsToDelete: string[] = [];

    for (const [dhKey, chainInfo] of Object.entries(state.processedChains)) {
      if (chainInfo.timestamp < expirationTime) {
        chainsToDelete.push(dhKey);
      }
    }

    // Delete expired chains (no secure zeroing needed - stores numbers, not crypto material)
    for (const dhKey of chainsToDelete) {
      delete state.processedChains[dhKey];
    }

    // Log cleanup if chains were removed
    if (chainsToDelete.length > 0) {
      logger.debug('Cleaned up expired processed chains', {
        category: 'E2EE',
        data: {
          operation: 'cleanupExpiredProcessedChains',
          removedCount: chainsToDelete.length,
          remainingCount: Object.keys(state.processedChains).length,
          maxAge: config.maxMessageKeyAge,
        },
      });
    }
  }

  // ========================================================================
  // Clean up expired receiverChains entries (v3 format)
  // ========================================================================
  if (state.receiverChains && state.receiverChains.length > 0) {
    let removedKeyCount = 0;
    const chainsToRemove: number[] = [];

    for (let ci = 0; ci < state.receiverChains.length; ci++) {
      const chain = state.receiverChains[ci]!;
      const keysToRemove: number[] = [];

      // Find expired keys in this chain
      for (let ki = 0; ki < chain.messageKeys.length; ki++) {
        if (chain.messageKeys[ki]!.timestamp < expirationTime) {
          keysToRemove.push(ki);
        }
      }

      // Remove expired keys (in reverse order to preserve indices)
      for (let i = keysToRemove.length - 1; i >= 0; i--) {
        const keyIdx = keysToRemove[i]!;
        const key = chain.messageKeys[keyIdx];
        if (key) {
          secureZero(key.seed);
        }
        chain.messageKeys.splice(keyIdx, 1);
        removedKeyCount++;
      }

      // Mark empty chains for removal
      if (chain.messageKeys.length === 0 && !chain.chainKey) {
        chainsToRemove.push(ci);
      }
    }

    // Remove empty chains (in reverse order)
    for (let i = chainsToRemove.length - 1; i >= 0; i--) {
      state.receiverChains.splice(chainsToRemove[i]!, 1);
    }

    if (removedKeyCount > 0 || chainsToRemove.length > 0) {
      logger.debug('Cleaned up expired receiver chain keys', {
        category: 'E2EE',
        data: {
          operation: 'cleanupExpiredReceiverChains',
          removedKeys: removedKeyCount,
          removedChains: chainsToRemove.length,
          remainingChains: state.receiverChains.length,
        },
      });
    }
  }
}

// ============================================================================
// Receiver Chain Management (v3 protobuf-compatible format)
// ============================================================================

/**
 * Find or create a receiver chain for a given ratchet key.
 *
 * If chain count exceeds MAX_RECEIVER_CHAINS (5), removes oldest chain.
 * The operation mutates only the selected receiving chain.
 *
 * @param state Session state with receiverChains
 * @param senderRatchetKey Sender's DH public key for this chain
 * @returns The existing or newly created receiver chain
 */
export function getOrCreateReceiverChain(
  state: DoubleRatchetState,
  senderRatchetKey: Base64,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): ReceiverChain {
  // Ensure receiverChains exists
  if (!state.receiverChains) {
    state.receiverChains = [];
  }

  // Find existing chain
  let chain = state.receiverChains.find((c) => c.senderRatchetKey === senderRatchetKey);

  if (!chain) {
    // Create new chain
    chain = {
      senderRatchetKey,
      chainKey: null,
      messageKeys: [],
    };

    // Trim oldest chain if at limit (FIFO)
    if (state.receiverChains.length >= MAX_RECEIVER_CHAINS) {
      const removed = state.receiverChains.shift();
      if (removed) {
        // Securely zero removed chain's message keys
        for (const key of removed.messageKeys) {
          secureZero(key.seed);
        }
        logger.debug('Evicted oldest receiver chain (MAX_RECEIVER_CHAINS reached)', {
          category: 'E2EE',
          data: {
            operation: 'receiver-chain-eviction',
            evictedRatchetKey: removed.senderRatchetKey.substring(0, 20) + '...',
            evictedKeyCount: removed.messageKeys.length,
          },
        });
      }
    }

    state.receiverChains.push(chain);
  }

  return chain;
}

/**
 * Count total message keys across all receiver chains.
 *
 * @param state Session state with receiverChains
 * @returns Total number of stored message keys
 */
export function countTotalMessageKeys(state: DoubleRatchetState): number {
  if (!state.receiverChains) {
    return 0;
  }
  return state.receiverChains.reduce((sum, chain) => sum + chain.messageKeys.length, 0);
}

/**
 * Evict oldest message key across all receiver chains (FIFO).
 *
 * If a chain becomes empty after eviction, it is removed.
 *
 * @param state Session state with receiverChains
 */
export function evictOldestMessageKey(
  state: DoubleRatchetState,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): void {
  if (!state.receiverChains || state.receiverChains.length === 0) {
    return;
  }

  let oldestTimestamp = Infinity;
  let oldestChainIdx = -1;
  let oldestKeyIdx = -1;

  // Find the oldest key across all chains
  for (let ci = 0; ci < state.receiverChains.length; ci++) {
    const chain = state.receiverChains[ci]!;
    for (let ki = 0; ki < chain.messageKeys.length; ki++) {
      const key = chain.messageKeys[ki]!;
      if (key.timestamp < oldestTimestamp) {
        oldestTimestamp = key.timestamp;
        oldestChainIdx = ci;
        oldestKeyIdx = ki;
      }
    }
  }

  // Remove the oldest key
  if (oldestChainIdx >= 0 && oldestKeyIdx >= 0) {
    const chain = state.receiverChains[oldestChainIdx]!;
    const removedKey = chain.messageKeys[oldestKeyIdx];

    // Securely zero the key before removal
    if (removedKey) {
      secureZero(removedKey.seed);
    }

    chain.messageKeys.splice(oldestKeyIdx, 1);

    // Keep empty chains for late out-of-order messages. Evict them only when
    // MAX_RECEIVER_CHAINS is exceeded.
    // Empty chains may still receive out-of-order messages.

    logger.debug('Evicted oldest message key (MAX_MESSAGE_KEYS reached)', {
      category: 'E2EE',
      data: {
        operation: 'message-key-eviction',
        timestamp: oldestTimestamp,
      },
    });
  }
}

/**
 * Store a skipped message key in the receiver chain.
 *
 * Two-tier eviction:
 * 1. Per-chain: FIFO eviction when chain exceeds MAX_MESSAGE_KEYS (2000)
 * 2. Global: FIFO eviction when total across all chains exceeds limit
 *
 * @param state Session state with receiverChains
 * @param senderRatchetKey Sender's DH public key
 * @param index Message counter (index in chain)
 * @param seed 32-byte message key seed
 * @param config Double Ratchet configuration
 */
export function storeMessageKeyInChain(
  state: DoubleRatchetState,
  senderRatchetKey: Base64,
  index: number,
  seed: Uint8Array,
  config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): void {
  const chain = getOrCreateReceiverChain(state, senderRatchetKey, logger);

  // Check if key already exists
  if (chain.messageKeys.some((k) => k.index === index)) {
    return; // Already stored
  }

  // Count total keys and evict if at limit (use config, not hardcoded constant)
  const totalKeys = countTotalMessageKeys(state);
  if (totalKeys >= config.maxMessageKeysStored) {
    evictOldestMessageKey(state, logger);
  }

  // Store new key
  chain.messageKeys.push({
    index,
    seed: bytesToBase64(seed),
    timestamp: Date.now(),
  });

  // Per-chain hard cap with FIFO eviction.
  if (chain.messageKeys.length > MAX_MESSAGE_KEYS) {
    const evicted = chain.messageKeys.shift();
    if (evicted) {
      secureZero(evicted.seed);
    }
  }
}

/**
 * Look up and consume a skipped message key from receiver chains.
 *
 * Returns the seed and removes it from storage. Each key can only be used once.
 *
 * @param state Session state with receiverChains
 * @param senderRatchetKey Sender's DH public key
 * @param index Message counter
 * @returns Message key seed if found, null otherwise
 */
export function consumeMessageKeyFromChain(
  state: DoubleRatchetState,
  senderRatchetKey: Base64,
  index: number
): Uint8Array | null {
  if (!state.receiverChains) {
    return null;
  }

  // Find the chain
  const chain = state.receiverChains.find((c) => c.senderRatchetKey === senderRatchetKey);

  if (!chain) {
    return null;
  }

  // Find the key
  const keyIdx = chain.messageKeys.findIndex((k) => k.index === index);
  if (keyIdx < 0) {
    return null;
  }

  // Remove and return the key
  const [removedKey] = chain.messageKeys.splice(keyIdx, 1);
  if (!removedKey) {
    return null;
  }

  const seed = base64ToBytes(removedKey.seed);

  // Keep empty chains for late out-of-order messages. Evict them only when
  // MAX_RECEIVER_CHAINS is exceeded.
  // Empty chains may still receive out-of-order messages.

  return seed;
}
