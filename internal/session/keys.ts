/**
 * Branded Types for Session Keys (Layer 5)
 *
 * These types provide compile-time safety for Double Ratchet session keys.
 * They prevent accidentally mixing different key types within the protocol.
 *
 * Key Hierarchy (Signal Protocol Section 2 + Section 3):
 * ```
 * Root Key (RK)           ─── Derives chain keys during DH ratchet
 *     │
 *     └── Chain Key (CK)  ─── Derives message keys and advances
 *             │
 *             └── Message Key (MK)  ─── Encrypts/decrypts single message
 * ```
 *
 * Note: This implementation uses Section 3 variant (plaintext headers + MAC).
 * Header encryption keys (HK) from Section 4 are not used.
 *
 * Signal Protocol Spec References:
 * - Section 2.2 - Root KDF Chain - RK derives CK
 * - Section 2.3 - Sending/Receiving Chains - CK derives MK
 * - Section 3 - Plaintext headers with identity-bound MAC authentication
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#the-kdf-chains
 */

import type { Base64 } from '../../types/utils';

// ============================================================================
// Brand Symbols (unique per type for strict type safety)
// ============================================================================
export {};
declare const __brand_root_key: unique symbol;
declare const __brand_chain_key: unique symbol;
declare const __brand_message_key: unique symbol;

// ============================================================================
// Session Key Types
// ============================================================================

/**
 * Root Key (RK) - Base64 encoded.
 *
 * Signal Protocol Section 2.2 -
 * "The root key is updated during each DH ratchet step by combining it
 * with a new DH output using KDF_RK."
 *
 * Security: Root key material. Used only for deriving chain keys.
 * NEVER used directly for encryption.
 *
 * Size: 32 bytes (256 bits), stored as Base64
 */
export type RootKey = Base64 & {
  readonly [__brand_root_key]: true;
};

/**
 * Chain Key (CK) - Base64 encoded.
 *
 * Signal Protocol Section 2.3 -
 * "Each message is encrypted using a unique message key derived from
 * the current chain key using KDF_CK. The chain key is also ratcheted
 * forward to provide forward secrecy."
 *
 * Two types per session:
 * - CKs: Sending chain key (for outgoing messages)
 * - CKr: Receiving chain key (for incoming messages)
 *
 * Security: Intermediate key material. Used only for deriving message keys.
 * Ratcheted after each use to give forward secrecy.
 *
 * Size: 32 bytes (256 bits), stored as Base64
 */
export type ChainKey = Base64 & {
  readonly [__brand_chain_key]: true;
};

/**
 * Message Key (MK) - Base64 encoded.
 *
 * Signal Protocol Section 2.3 -
 * "Message keys are derived from chain keys using KDF_CK. Each message
 * uses a unique message key that is deleted after use."
 *
 * Usage: Expanded via HKDF to produce:
 * - 32 bytes: AES-256 encryption key
 * - 32 bytes: HMAC-SHA256 authentication key
 * - 16 bytes: AES-CBC IV
 *
 * Security: MUST be deleted after use. Storage for out-of-order messages
 * MUST implement expiration (the reference implementation recommends 1 week max).
 *
 * Size: 32 bytes (256 bits), stored as Base64
 */
export type MessageKey = Base64 & {
  readonly [__brand_message_key]: true;
};

// ============================================================================
// Constructor Functions
// ============================================================================

/**
 * Assert Base64 string as Root Key.
 *
 * @param b64 - Base64-encoded key (must be 32 bytes when decoded)
 * @returns Branded RootKey
 */
export function asRootKey(b64: Base64): RootKey {
  return b64 as RootKey;
}

/**
 * Assert Base64 string as Chain Key.
 *
 * @param b64 - Base64-encoded key (must be 32 bytes when decoded)
 * @returns Branded ChainKey
 */
export function asChainKey(b64: Base64): ChainKey {
  return b64 as ChainKey;
}

/**
 * Assert Base64 string as Message Key.
 *
 * @param b64 - Base64-encoded key (must be 32 bytes when decoded)
 * @returns Branded MessageKey
 */
export function asMessageKey(b64: Base64): MessageKey {
  return b64 as MessageKey;
}

// ============================================================================
// Type-Safe KDF Output Types
// ============================================================================

/**
 * Output from KDF_RK (Root Key KDF).
 *
 * Signal Protocol Section 2.2 -
 * KDF_RK(rk, dh_out) returns (new_root_key, chain_key)
 */
export interface KDFRootKeyOutput {
  /** New root key for next DH ratchet */
  rootKey: RootKey;
  /** Chain key for new sending/receiving chain */
  chainKey: ChainKey;
}

/**
 * Output from KDF_CK (Chain Key KDF).
 *
 * Signal Protocol Section 2.3 -
 * KDF_CK(ck) returns (next_chain_key, message_key)
 *
 * Note: Header key derivation (Section 4) is not used in this implementation.
 * We use Section 3 variant with plaintext headers + MAC authentication.
 */
export interface KDFChainKeyOutput {
  /** Next chain key (ratcheted forward) */
  chainKey: ChainKey;
  /** Message key for encryption/decryption */
  messageKey: MessageKey;
}

/**
 * Expanded message key for encryption operations.
 *
 * Signal Protocol Section 2.4 -
 * Message key is expanded via HKDF to derive encryption parameters.
 */
export interface ExpandedMessageKey {
  /** 32-byte AES-256 encryption key */
  encryptionKey: Uint8Array;
  /** 32-byte HMAC-SHA256 authentication key */
  authKey: Uint8Array;
  /** 16-byte AES-CBC initialization vector */
  iv: Uint8Array;
}

// ============================================================================
// Session Key State Types
// ============================================================================

/**
 * Double Ratchet sending chain state.
 *
 * Manages the sending chain key and message counter.
 *
 * Note: Uses Section 3 variant (plaintext headers + MAC).
 * Header keys are not used.
 */
export interface SendingChainState {
  /** Current sending chain key */
  CKs: ChainKey;
  /** Number of messages sent in current chain */
  Ns: number;
}

/**
 * Double Ratchet receiving chain state.
 *
 * Manages the receiving chain key and message counter.
 *
 * Note: Uses Section 3 variant (plaintext headers + MAC).
 * Header keys are not used.
 */
export interface ReceivingChainState {
  /** Current receiving chain key */
  CKr: ChainKey;
  /** Number of messages received in current chain */
  Nr: number;
}

/**
 * Skipped message key entry with metadata.
 *
 * Signal Protocol Section 4.6 + Section 8.4 -
 * Skipped keys are indexed by (header_key, message_number) and
 * should expire after ~1 week to limit storage and prevent attacks.
 */
export interface SkippedMessageKeyEntry {
  /** The skipped message key */
  key: MessageKey;
  /** Timestamp when key was stored (for expiration) */
  timestamp: number;
}

/**
 * Skipped message keys dictionary.
 *
 * Key format: "DHr:N" where DHr is Base64 DH public key and N is message number.
 *
 * Signal Protocol Section 3.5 covers out-of-order messages. When a message
 * arrives out of order, store the skipped message keys for later decryption.
 *
 * Note: We use DHr-based keys (Section 3) instead of HKr-based keys (Section 4).
 */
export type SkippedMessageKeyDict = Record<string, SkippedMessageKeyEntry>;

// ============================================================================
// Constants
// ============================================================================

/**
 * Size of session keys in bytes (before Base64 encoding)
 */
export const SESSION_KEY_BYTES = 32;

/**
 * Maximum forward jumps in message counter per ratchet step.
 *
 * Prevents DoS attacks where an attacker sends messages with large gaps
 * in counters, forcing excessive key derivation and storage.
 *
 */
export const MAX_FORWARD_JUMPS = 25000;

/**
 * Default message key expiration time (1 week in milliseconds).
 *
 * Signal Protocol Section 8.4 -
 * "A recommended policy is to delete message keys more than one week old."
 */
export const MESSAGE_KEY_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;
