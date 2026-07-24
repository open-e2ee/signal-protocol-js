/**
 * Ratcheted Authenticator
 *
 * Provides internal message authentication for ML-KEM Braid messages.
 *
 * @module ml-kem-braid/authenticator
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented
 *
 * ## MAC Architecture Overview
 *
 * ML-KEM Braid authenticates different message components differently:
 *
 * | Component | Size | MAC Strategy | Notes |
 * |-----------|------|--------------|-------|
 * | Header | 96 bytes (64 + 32 MAC) | Explicit `MacHdr()` | Contains ek_seed + hek |
 * | EK (Encapsulation Key) | 1,152 bytes (NO MAC) | Hash binding via `hek` | Saves 32 bytes |
 * | CT1 | 960 bytes (NO MAC) | Combined with CT2 | Verified together |
 * | CT2 | 160 bytes (128 + 32 MAC) | `MacCt(ct1 || ct2)` | Combined MAC |
 *
 * **Key Insight**: EK is NOT explicitly MACed. Instead, the header contains
 * `hek`, and since the header IS MACed, EK integrity is verified through hash
 * binding. This SDK follows the ML-KEM Braid specification and computes
 * `hek = SHA3-256(ek_seed || ek_vector)`.
 *
 * ## Hash Binding for EK Authentication
 *
 * The encapsulation key is authenticated as specified:
 *
 * ```
 * hek = SHA3-256(ek_seed || ek_vector)
 * ```
 *
 * The header contains `hek` and is MAC-authenticated, so verifying
 * the hash provides integrity for the EK vector without an explicit MAC.
 *
 * **Security Rationale**:
 * 1. `hek` is transmitted in the authenticated header (MAC-protected)
 * 2. Any modification to EK will cause hash mismatch
 * 3. Saves 32 bytes vs explicit MAC (1,152 vs 1,184 bytes)
 * 4. Enables EK to fit in 36 chunks for interleaved encoding
 *
 * ## Protocol Flow with MAC Architecture
 *
 * ```
 * Alice (Initiator)                    Bob (Responder)
 * ════════════════                     ═══════════════
 *
 * KeyGen() → (dk, ek_seed, ek_vector)
 *   hek = SHA3-256(ek_seed || ek_vector) // ML-KEM Braid specification
 *   header = ek_seed || hek (64 bytes)
 *   header_mac = MacHdr(auth, epoch, header)
 *            ──── Header + MAC (96 bytes) ────►
 *                                      VfyHdr(auth, epoch, header, mac)
 *                                      Store ek_seed, hek
 *            ──── EK chunks (1,152 bytes) ────►
 *                                      Reassemble ek_vector
 *                                      Verify specification HEK == hek
 *
 *                                      Encaps1(ek_seed, hek) → ct1, secret
 *            ◄──── CT1 chunks (960 bytes) ────
 * Store ct1 (defer verification)
 *                                      Encaps2(secret, ek_vector) → ct2
 *                                      combined_mac = MacCt(auth, epoch, ct1 || ct2)
 *            ◄──── CT2 + MAC (160 bytes) ────
 * Reassemble ct1 || ct2
 * VfyCt(auth, epoch, ct1 || ct2, mac)
 * Decaps(dk, ct1, ct2) → shared_secret
 *            ═══ Shared Secret ═══     Same shared secret
 * ```
 *
 * ## Security Considerations
 *
 * 1. **Forward Secrecy**: Authenticator state ratchets forward with each epoch.
 *    Past MACs cannot be computed from current state.
 *
 * 2. **EK Integrity**: Hash binding provides the same integrity guarantees
 *    as explicit MAC while saving bandwidth.
 *
 * 3. **CT1+CT2 Binding**: Combined MAC prevents mix-and-match attacks where
 *    ct1 from one epoch is combined with ct2 from another.
 *
 * 4. **Best-Effort Full-Scan Verification**: Equal-length MAC comparisons use
 *    `constantTimeEqual()` without a source-level early exit. JavaScript/JIT
 *    execution has no hard constant-time guarantee.
 *
 * 5. **Epoch Binding**: MACs include epoch number to prevent cross-epoch
 *    replay attacks.
 */

import type { AuthenticatorState, IAuthenticator } from './types';
import { PROTOCOL_CONSTANTS } from './types';
import { AuthenticatorError } from './errors';
import { KDF_AUTH, uint64ToBytes } from './kdf';
import { hmac } from '../../../crypto/symmetric/hmac';
import { constantTimeEqual, secureZeroBytes } from '../../../crypto';

/**
 * Ratcheted Authenticator Implementation
 *
 * The authenticator provides per-epoch MACs for headers and ciphertexts,
 * preventing forgery and epoch confusion attacks.
 */
export {};
export class RatchetedAuthenticator implements IAuthenticator {
  /**
   * Initialize authenticator for new session
   *
   * Called once at session establishment with PQXDH shared secret.
   *
   * @param state - Authenticator state to initialize
   * @param epoch - Initial epoch number (typically 0)
   * @param initial_key - Initial shared secret from PQXDH
   */
  async Init(state: AuthenticatorState, epoch: bigint, initial_key: Uint8Array): Promise<void> {
    // Initialize root_key to zeros
    const previousRootKey = state.root_key;
    const previousMacKey = state.mac_key;
    state.root_key = new Uint8Array(32);
    if (previousRootKey !== initial_key) secureZeroBytes(previousRootKey);
    if (previousMacKey !== initial_key) secureZeroBytes(previousMacKey);

    // Derive initial keys using Update
    await this.Update(state, epoch, initial_key);
  }

  /**
   * Update authenticator for new epoch
   *
   * Called when a new shared secret is derived from ML-KEM Braid.
   *
   * @param state - Authenticator state to update
   * @param epoch - New epoch number
   * @param key - Shared secret for this epoch
   */
  async Update(state: AuthenticatorState, epoch: bigint, key: Uint8Array): Promise<void> {
    // Derive new root_key and mac_key using KDF_AUTH
    const derived = await KDF_AUTH(state.root_key, key, epoch);
    try {
      const nextRootKey = derived.slice(0, 32);
      const nextMacKey = derived.slice(32, 64);
      const previousRootKey = state.root_key;
      const previousMacKey = state.mac_key;

      state.root_key = nextRootKey;
      state.mac_key = nextMacKey;
      if (previousRootKey !== key) secureZeroBytes(previousRootKey);
      if (previousMacKey !== key) secureZeroBytes(previousMacKey);
    } finally {
      secureZeroBytes(derived);
    }
  }

  /**
   * Generate MAC for header
   *
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param header - Header data (64 bytes: ek_seed || hek)
   * @returns 32-byte HMAC-SHA256
   */
  MacHdr(state: AuthenticatorState, epoch: bigint, header: Uint8Array): Uint8Array {
    // Build MAC input: PROTOCOL_INFO || ":ekheader" || epoch || header
    const info = this.buildMacInput(':ekheader', epoch, header);

    // Compute HMAC-SHA256(mac_key, info)
    return hmac(state.mac_key, info);
  }

  /**
   * Generate MAC for ciphertext
   *
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param ciphertext - Ciphertext data (ct1 or ct2)
   * @returns 32-byte HMAC-SHA256
   */
  MacCt(state: AuthenticatorState, epoch: bigint, ciphertext: Uint8Array): Uint8Array {
    // Build MAC input: PROTOCOL_INFO || ":ciphertext" || epoch || ciphertext
    const info = this.buildMacInput(':ciphertext', epoch, ciphertext);

    // Compute HMAC-SHA256(mac_key, info)
    return hmac(state.mac_key, info);
  }

  /**
   * Verify header MAC
   *
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param header - Header data
   * @param expected_mac - Expected MAC value (32 bytes)
   * @throws Error if MAC verification fails
   */
  VfyHdr(
    state: AuthenticatorState,
    epoch: bigint,
    header: Uint8Array,
    expected_mac: Uint8Array
  ): void {
    const computed = this.MacHdr(state, epoch, header);

    if (!constantTimeEqual(computed, expected_mac)) {
      throw AuthenticatorError.macVerificationFailed('header', epoch);
    }
  }

  /**
   * Verify ciphertext MAC
   *
   * @param state - Current authenticator state
   * @param epoch - Epoch number
   * @param ciphertext - Ciphertext data
   * @param expected_mac - Expected MAC value (32 bytes)
   * @throws Error if MAC verification fails
   */
  VfyCt(
    state: AuthenticatorState,
    epoch: bigint,
    ciphertext: Uint8Array,
    expected_mac: Uint8Array
  ): void {
    const computed = this.MacCt(state, epoch, ciphertext);

    if (!constantTimeEqual(computed, expected_mac)) {
      throw AuthenticatorError.macVerificationFailed('ciphertext', epoch);
    }
  }

  // ===========================================================================
  // Private helpers
  // ===========================================================================

  /**
   * Build MAC input with protocol info and domain separator
   */
  private buildMacInput(domain: string, epoch: bigint, data: Uint8Array): Uint8Array {
    const protocolInfo = new TextEncoder().encode(PROTOCOL_CONSTANTS.PROTOCOL_INFO);
    const domainBytes = new TextEncoder().encode(domain);
    const epochBytes = uint64ToBytes(epoch);

    // Concatenate: PROTOCOL_INFO || domain || epoch || data
    const result = new Uint8Array(
      protocolInfo.length + domainBytes.length + epochBytes.length + data.length
    );

    let offset = 0;
    result.set(protocolInfo, offset);
    offset += protocolInfo.length;
    result.set(domainBytes, offset);
    offset += domainBytes.length;
    result.set(epochBytes, offset);
    offset += epochBytes.length;
    result.set(data, offset);

    return result;
  }
}

/**
 * Create a new authenticator instance
 */
export function createAuthenticator(): IAuthenticator {
  return new RatchetedAuthenticator();
}

/**
 * Initialize a new authenticator state
 *
 * @param initial_key - Initial shared secret from PQXDH
 * @returns Initialized authenticator state
 */
export async function initAuthenticatorState(initial_key: Uint8Array): Promise<AuthenticatorState> {
  const state: AuthenticatorState = {
    root_key: new Uint8Array(32),
    mac_key: new Uint8Array(32),
  };

  const auth = createAuthenticator();
  await auth.Init(state, 0n, initial_key);

  return state;
}
