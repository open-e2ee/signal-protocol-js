/**
 * HKDF (HMAC-based Key Derivation Function)
 *
 * Implements RFC 5869 HKDF using HMAC-SHA256.
 * Used throughout the Signal Protocol for deriving keys from shared secrets.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 * @see https://signal.org/docs/specifications/doubleratchet/#the-kdf-chains
 */

import { hmac } from '../symmetric/hmac';
import { stringToBytes, concatBytes, secureZeroBytes } from '../utils';

// ============================================================================
// Derived Key Branded Type
// ============================================================================
export {};
declare const __brand_derived_key: unique symbol;

/**
 * Key material derived through KDF (HKDF-SHA256).
 *
 * This is the output of key derivation functions and is safe to use
 * for encryption operations.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#the-kdf-chains
 */
export type DerivedKey = Uint8Array & {
  readonly [__brand_derived_key]: true;
};

/**
 * Size of derived keys in bytes (default HKDF output)
 */
export const DERIVED_KEY_BYTES = 32;

/**
 * Assert raw bytes as derived key.
 *
 * @param bytes - Output from KDF function
 * @returns Branded DerivedKey
 */
export function asDerivedKey(bytes: Uint8Array): DerivedKey {
  return bytes as DerivedKey;
}

// ============================================================================
// HKDF Functions
// ============================================================================

/**
 * HKDF (HMAC-based Key Derivation Function)
 *
 * Implements the Extract-then-Expand paradigm from RFC 5869.
 * Used for deriving keys from shared secrets.
 *
 * @param ikm Input Key Material
 * @param salt Salt value (can be empty)
 * @param info Context-specific info string
 * @param length Desired output length in bytes
 * @returns Derived key material
 */
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  // HKDF-Extract: derive pseudorandom key (PRK)
  const prk = hmac(salt.length > 0 ? salt : new Uint8Array(32), ikm);

  try {
    // HKDF-Expand: expand PRK to desired length. The returned bytes are a
    // separate allocation; this function owns and clears the PRK.
    return await hkdfExpand(prk, info, length);
  } finally {
    secureZeroBytes(prk);
  }
}

/**
 * HKDF-Expand step
 *
 * Expands the PRK to the desired length using HMAC iterations.
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const hashLength = 32; // SHA-256 output
  const n = Math.ceil(length / hashLength);

  if (n > 255) {
    throw new Error('HKDF length too long');
  }

  let t: Uint8Array = new Uint8Array(0);
  const result = new Uint8Array(n * hashLength);
  try {
    for (let i = 0; i < n; i++) {
      const data = new Uint8Array(t.length + info.length + 1);
      try {
        data.set(t, 0);
        data.set(info, t.length);
        data.set([i + 1], t.length + info.length);

        const previousT = t;
        t = hmac(prk, data);
        secureZeroBytes(previousT);
        result.set(t, i * hashLength);
      } finally {
        secureZeroBytes(data);
      }
    }

    return result.slice(0, length);
  } finally {
    secureZeroBytes(t);
    secureZeroBytes(result);
  }
}

// ============================================================================
// Double Ratchet Key Derivation Functions
// ============================================================================

/**
 * KDF_RK: Root Key Derivation Function
 *
 * Derives new root key and chain key from:
 * - Current root key
 * - DH output from ratchet step
 *
 * This is called during the DH ratchet step to derive new sending/receiving chains.
 * Returns: [new_root_key (32 bytes), chain_key (32 bytes)]
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - KDF_RK(rk, dh_out)
 * @see https://signal.org/docs/specifications/doubleratchet/#the-kdf-chains - Root KDF Chain explanation
 */
export async function kdfRootKey(
  rootKey: Uint8Array,
  dhOutput: Uint8Array
): Promise<{ rootKey: Uint8Array; chainKey: Uint8Array }> {
  // Use HKDF with DH output as input key material
  const salt = rootKey; // Current root key is used as salt
  // Domain-separate root-key derivation.
  const info = stringToBytes('WhisperRatchet');

  // Derive 64 bytes: 32 for new root key, 32 for chain key
  const derived = await hkdf(dhOutput, salt, info, 64);

  try {
    return {
      rootKey: derived.slice(0, 32),
      chainKey: derived.slice(32, 64),
    };
  } finally {
    secureZeroBytes(derived);
  }
}

/**
 * KDF_CK: Chain Key Derivation Function
 *
 * Implements Signal Protocol Section 2.3 KDF_CK (Section 3 variant - no header encryption).
 *
 * Derives new chain key and message key from current chain key.
 * This implements the symmetric ratchet step.
 *
 * Per Signal Protocol specification (Section 3):
 * - message_key = HMAC-SHA256(chain_key, 0x01)
 * - next_chain_key = HMAC-SHA256(chain_key, 0x02)
 *
 * Each message gets a unique key, and the chain key is ratcheted forward
 * so that past messages can't be decrypted even if the current chain key
 * is compromised (forward secrecy).
 *
 * Returns: [chain_key (32 bytes), message_key (32 bytes)]
 *
 * @see Signal Protocol Specification Section 2.3 - External Functions - KDF_CK
 */
export function kdfChainKey(chainKey: Uint8Array): {
  chainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  // Signal Protocol spec (Section 3): Use HMAC-SHA256 with constants 0x01 and 0x02
  const messageKey = hmac(chainKey, new Uint8Array([0x01]));
  const nextChainKey = hmac(chainKey, new Uint8Array([0x02]));

  return {
    chainKey: nextChainKey, // 32 bytes
    messageKey: messageKey, // 32 bytes (will be expanded to 80 bytes for encryption)
  };
}

/**
 * Expand Message Key
 *
 * Expands a 32-byte message key to 80 bytes using HKDF:
 * - 32 bytes for AES-256 encryption key
 * - 32 bytes for HMAC-SHA256 authentication key
 * - 16 bytes for AES-CBC IV
 *
 * Per Signal Protocol specification, the message key from KDF_CK
 * must be expanded before use in encryption.
 *
 * - Classical Double Ratchet uses zero-filled salt (default behavior)
 * - Triple Ratchet passes the PQ message key as optional salt
 *
 * @param messageKey 32-byte message key from KDF_CK
 * @param optionalSalt Optional salt (PQ message key in Triple Ratchet mode)
 * @returns {encryptionKey, authKey, iv} for AES-CBC + HMAC
 */
export async function expandMessageKey(
  messageKey: Uint8Array,
  optionalSalt?: Uint8Array
): Promise<{
  encryptionKey: Uint8Array;
  authKey: Uint8Array;
  iv: Uint8Array;
}> {
  const MESSAGE_KEY_SIZE = 80; // Signal Protocol: 32 enc + 32 auth + 16 IV

  // Use HKDF to expand 32 bytes to 80 bytes.
  // Default is zero-filled salt for classical Double Ratchet.
  // Triple Ratchet callers can pass PQ key material as optionalSalt.
  const salt = optionalSalt ?? new Uint8Array(32);
  // Domain-separate message-key expansion.
  const info = stringToBytes('WhisperMessageKeys');

  const expanded = await hkdf(messageKey, salt, info, MESSAGE_KEY_SIZE);

  try {
    return {
      encryptionKey: expanded.slice(0, 32), // First 32 bytes for AES-256
      authKey: expanded.slice(32, 64), // Next 32 bytes for HMAC-SHA256
      iv: expanded.slice(64, 80), // Last 16 bytes for CBC IV
    };
  } finally {
    secureZeroBytes(expanded);
  }
}

// ============================================================================
// Triple Ratchet Key Mixing (Signal Protocol Section 6)
// ============================================================================

/**
 * KDF_HYBRID: Combine EC and post-quantum message keys (Section 6.3)
 *
 * Signal Protocol Section 6.3 -
 * "The Triple Ratchet combines message keys from both the EC Double Ratchet
 * and the Sparse Post-Quantum Ratchet using KDF_HYBRID(), which mixes the
 * keys using HKDF to provide hybrid security."
 *
 * Security intent: the output combines independent EC and post-quantum
 * contributions. End-to-end hybrid guarantees remain conditional on correct
 * domain separation, authenticated protocol context, uncompromised state, and
 * at least one contribution remaining secret; this helper alone is not proof.
 *
 * Implementation:
 * - Uses HKDF with PQ key as salt and EC key as input material
 * - Info string binds key to Triple Ratchet protocol version
 * - Output is 32 bytes for AES-256-GCM encryption
 *
 * ## Runtime note
 *
 * SessionCipher mixes the post-quantum contribution as optional HKDF salt
 * during message-key expansion.
 *
 * kdfHybrid() is retained as a spec-aligned helper for explicit Section 6.3
 * composition where a standalone 32-byte hybrid key is useful.
 *
 * @param ec_mk - Message key from EC Double Ratchet (32 bytes)
 * @param pq_mk - Message key from SPQR (32 bytes)
 * @returns Combined message key (32 bytes)
 *
 * @example
 * ```typescript
 * // Get keys from both ratchets
 * const ec_mk = await ecRatchetSendKey(state.ec_state);
 * const pq_mk = await deriveSPQRSendKey(state.spqrState);
 *
 * // Combine with hybrid KDF
 * const mk = await kdfHybrid(ec_mk, pq_mk);
 *
 * // Use combined key for encryption
 * const ciphertext = await aesGcmEncrypt(mk, plaintext, ad);
 * ```
 */
export async function kdfHybrid(
  ec_mk: Uint8Array,
  pq_mk: Uint8Array,
  infoString?: string
): Promise<Uint8Array> {
  // Validate inputs
  if (ec_mk.length !== 32) {
    throw new Error('EC message key must be 32 bytes');
  }
  if (pq_mk.length !== 32) {
    throw new Error('PQ message key must be 32 bytes');
  }

  // Signal Protocol Section 6.3 - Triple Ratchet hybrid key derivation
  // TR_PROTOCOL_INFO is application-defined per spec
  // We use the protocol domain string "Signal Triple Ratchet V1".
  // Note: TR_PROTOCOL_INFO is imported at module level to avoid circular deps
  const info = stringToBytes(infoString ?? 'Signal Triple Ratchet V1');

  // HKDF with PQ key as salt and EC key as input material.
  // This ensures security if EITHER key is compromised
  return await hkdf(
    ec_mk, // ikm: EC key as input key material
    pq_mk, // salt: PQ key as salt
    info, // info: TR_PROTOCOL_INFO
    32 // length: 32 bytes for AES-256
  );
}

// Spec-compliant alias
export const KDF_HYBRID = kdfHybrid;

// ============================================================================
// TR_PROTOCOL_INFO: Triple Ratchet Protocol Identifier
// ============================================================================

/**
 * TR_PROTOCOL_INFO: Triple Ratchet Protocol Identifier (Section 6.3)
 *
 * Used for KDF_HYBRID to combine EC and PQ message keys.
 * The Signal Protocol specification defines this as an application-specific constant that uniquely
 * identifies the protocol and version in use."
 *
 * These protocol domain strings use the "Signal ... V1 ..." convention.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#combining-double-ratchets-for-hybrid-security
 */
export const TR_PROTOCOL_INFO = 'Signal Triple Ratchet V1';

// ============================================================================
// SPQR Chain Key Derivation (Profile)
// ============================================================================

/**
 * SPQR Info Strings (Profile)
 *
 * CHAIN_START deliberately uses two spaces before "Start". The exact byte
 * sequence is part of key derivation and therefore cannot be normalized.
 *
 * @see https://signal.org/blog/spqr/
 */
export const SPQR_INFO_STRINGS = {
  /** Default prefix for info strings (trailing space) */
  PREFIX: 'Signal PQ Ratchet V1 Chain ',

  /** Suffixes for custom prefixes (single space before Start) */
  SUFFIX_START: 'Start',
  SUFFIX_ADD_EPOCH: 'Add Epoch',
  SUFFIX_NEXT: 'Next',

  /** Initial chain setup from root key (96 bytes output) - TWO spaces before Start (Signal quirk) */
  CHAIN_START: 'Signal PQ Ratchet V1 Chain  Start',
  /** Epoch advancement after PQ ratchet (96 bytes output) */
  CHAIN_ADD_EPOCH: 'Signal PQ Ratchet V1 Chain Add Epoch',
  /** Per-message chain advancement (64 bytes output) */
  CHAIN_NEXT: 'Signal PQ Ratchet V1 Chain Next',
} as const;

/**
 * Resolved SPQR info strings for KDF operations.
 */
export interface ResolvedSPQRInfoStrings {
  chainStart: string;
  chainAddEpoch: string;
  chainNext: string;
}

/**
 * Resolve SPQR info strings from configuration.
 *
 * Priority: individual strings > prefix-derived > pinned-reference defaults
 *
 * When no prefix is provided, uses pinned-reference defaults (including the
 * double-space quirk in CHAIN_START). When a custom prefix is provided,
 * generates clean strings without the quirk.
 *
 * @param config Optional configuration with prefix and/or individual strings
 * @returns Resolved info strings for all three KDF operations
 */
export function resolveSPQRInfoStrings(config?: {
  prefix?: string;
  chainStart?: string;
  chainAddEpoch?: string;
  chainNext?: string;
}): ResolvedSPQRInfoStrings {
  // If custom prefix is provided, derive strings from it (no double-space quirk)
  if (config?.prefix !== undefined) {
    const prefix = config.prefix;
    return {
      chainStart: config.chainStart ?? `${prefix}${SPQR_INFO_STRINGS.SUFFIX_START}`,
      chainAddEpoch: config.chainAddEpoch ?? `${prefix}${SPQR_INFO_STRINGS.SUFFIX_ADD_EPOCH}`,
      chainNext: config.chainNext ?? `${prefix}${SPQR_INFO_STRINGS.SUFFIX_NEXT}`,
    };
  }

  // No custom prefix: use pinned-reference defaults (with double-space quirk)
  return {
    chainStart: config?.chainStart ?? SPQR_INFO_STRINGS.CHAIN_START,
    chainAddEpoch: config?.chainAddEpoch ?? SPQR_INFO_STRINGS.CHAIN_ADD_EPOCH,
    chainNext: config?.chainNext ?? SPQR_INFO_STRINGS.CHAIN_NEXT,
  };
}

/**
 * KDF_CK_SPQR: SPQR Chain Key Derivation Function (Profile)
 *
 * Derives next chain key and message key from current chain key and message number.
 * This implements the SPQR symmetric ratchet step.
 *
 * Unlike standard KDF_CK which uses 0x01/0x02/0x03 constants, SPQR uses HKDF
 * with a 4-byte big-endian index prefix for domain separation.
 *
 * Per the profile:
 * - IKM = chain_key (32 bytes)
 * - Salt = [0; 32] (32 zero bytes)
 * - Info = [4-byte BE counter] || info_string
 * - Output: 64 bytes split as [new_chain_key (32)] || [message_key (32)]
 *
 * @param chainKey Current chain key (32 bytes)
 * @param index Message counter (1-indexed per profile: counter is pre-incremented)
 * @param infoString Optional custom info string (default: pinned-reference value)
 * @returns {chainKey, messageKey} - New chain key and message key (each 32 bytes)
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 */
export async function kdfChainKeySPQR(
  chainKey: Uint8Array,
  index: number,
  infoString: string = SPQR_INFO_STRINGS.CHAIN_NEXT
): Promise<{ chainKey: Uint8Array; messageKey: Uint8Array }> {
  if (chainKey.length !== 32) {
    throw new Error('Chain key must be 32 bytes');
  }
  if (index < 0 || index > 0xffffffff) {
    throw new Error('Index must be 0 to 2^32-1');
  }

  // Counter goes in info string, NOT IKM
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, index, false); // false = big-endian
  const info = concatBytes(counterBytes, stringToBytes(infoString));

  // IKM = chain_key only, salt = 32 zero bytes
  const derived = await hkdf(chainKey, new Uint8Array(32), info, 64);

  try {
    return {
      chainKey: derived.slice(0, 32), // Next chain key
      messageKey: derived.slice(32, 64), // Message key for this message
    };
  } finally {
    secureZeroBytes(derived);
  }
}

/**
 * KDF_SPQR_INIT: Initialize SPQR chains from root key (Profile)
 *
 * Derives initial chain keys for both parties from the shared root key
 * established during session setup (from PQXDH).
 *
 * Output: 96 bytes split as:
 * - [0:32]  - New root key
 * - [32:64] - A2B (Alice-to-Bob) initial chain key
 * - [64:96] - B2A (Bob-to-Alice) initial chain key
 *
 * Direction determines which keys are CKs (send) vs CKr (receive):
 * - A2B direction: CKs = [32:64], CKr = [64:96]
 * - B2A direction: CKs = [64:96], CKr = [32:64]
 *
 * @param rootKey Root key from PQXDH session establishment (32 bytes)
 * @param infoString Optional custom info string (default: pinned-reference value with double space)
 * @returns {rootKey, a2bChainKey, b2aChainKey} - All 32 bytes each
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 */
export async function kdfSpqrInit(
  rootKey: Uint8Array,
  infoString: string = SPQR_INFO_STRINGS.CHAIN_START
): Promise<{ rootKey: Uint8Array; a2bChainKey: Uint8Array; b2aChainKey: Uint8Array }> {
  if (rootKey.length !== 32) {
    throw new Error('Root key must be 32 bytes');
  }

  const info = stringToBytes(infoString);
  const derived = await hkdf(rootKey, new Uint8Array(0), info, 96);

  try {
    return {
      rootKey: derived.slice(0, 32), // New root key for next epoch
      a2bChainKey: derived.slice(32, 64), // Alice's send chain / Bob's receive chain
      b2aChainKey: derived.slice(64, 96), // Bob's send chain / Alice's receive chain
    };
  } finally {
    secureZeroBytes(derived);
  }
}

/**
 * KDF_SPQR_EPOCH: Advance SPQR epoch from Kyber shared secret (Profile)
 *
 * Called during post-quantum ratchet step when processing a new Kyber ciphertext.
 * Derives new root key and chain keys for the next epoch.
 *
 * Input: Current root key as salt, Kyber shared secret as IKM
 * Output: 96 bytes split as [root_key] || [a2b_chain] || [b2a_chain]
 *
 * @param kyberSharedSecret Shared secret from ML-KEM-768 decapsulation (32 bytes)
 * @param currentRootKey Current root key as salt (32 bytes)
 * @param infoString Optional custom info string (default: pinned-reference value)
 * @returns {rootKey, a2bChainKey, b2aChainKey} - All 32 bytes each
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 */
export async function kdfSpqrEpoch(
  kyberSharedSecret: Uint8Array,
  currentRootKey: Uint8Array,
  infoString: string = SPQR_INFO_STRINGS.CHAIN_ADD_EPOCH
): Promise<{ rootKey: Uint8Array; a2bChainKey: Uint8Array; b2aChainKey: Uint8Array }> {
  if (kyberSharedSecret.length !== 32) {
    throw new Error('Kyber shared secret must be 32 bytes');
  }
  if (currentRootKey.length !== 32) {
    throw new Error('Current root key must be 32 bytes');
  }

  const info = stringToBytes(infoString);
  // Use Kyber secret as IKM, current root key as salt (matches Signal)
  const derived = await hkdf(kyberSharedSecret, currentRootKey, info, 96);

  try {
    return {
      rootKey: derived.slice(0, 32), // New root key
      a2bChainKey: derived.slice(32, 64), // A2B chain key
      b2aChainKey: derived.slice(64, 96), // B2A chain key
    };
  } finally {
    secureZeroBytes(derived);
  }
}

// Spec-compliant aliases (uppercase for specification matching)
export const KDF_RK = kdfRootKey;
export const KDF_CK = kdfChainKey;
export const KDF_CK_SPQR = kdfChainKeySPQR;
export const KDF_SPQR_INIT = kdfSpqrInit;
export const KDF_SPQR_EPOCH = kdfSpqrEpoch;
