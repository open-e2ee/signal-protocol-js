/**
 * Session Builder Types
 *
 * Type definitions for the SessionBuilder class, which handles
 * session establishment via X3DH/PQXDH key agreement.
 *
 * Session Identification:
 * - A ProtocolAddress (userId:deviceId) LOOKS UP a session
 * - A baseKey (initiator's ephemeral public key) IDENTIFIES a session STATE
 * - No sessionId remains. Use remoteAddress for lookup, baseKey for state ID
 *
 * @see https://signal.org/docs/specifications/x3dh/
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import type {
  IdentityKeyPair,
  PreKeyBundle,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  IdentityType,
} from '../../keys';
import type { ISignalProtocolLocalStore, PreKeyMessage, SessionState } from '../../types';
import type { ProtocolAddress } from '../../types/address';
import type { ProtocolStrategyConfig } from '../../types';
import type { ILogger } from '../../logger';

// ============================================================================
// SessionBuilder Input Types
// ============================================================================

/**
 * Input for building an initiator (Alice) session
 *
 * Note: no sessionId remains. Two values identify a session:
 * - Lookup: remoteAddress (ProtocolAddress)
 * - State ID: baseKey (set automatically from ephemeral key)
 */
export {};
export interface SessionBuilderInitiatorInput {
  /** Local user's protocol address */
  localAddress: ProtocolAddress;
  /** Remote user's protocol address (used for session lookup) */
  remoteAddress: ProtocolAddress;
  /** Our identity key pair */
  identityKeyPair: IdentityKeyPair;
  /** Partner's prekey bundle from server */
  prekeyBundle: PreKeyBundle;
  /** Partner account identity namespace selected when fetching the bundle. */
  recipientIdentityType: IdentityType;
  /** Protocol strategy configuration (optional) */
  protocolStrategy?: ProtocolStrategyConfig;
  /** Resolved logger for session establishment */
  logger?: Required<ILogger>;
}

/**
 * Input for building a responder (Bob) session
 *
 * Note: no sessionId remains. Two values identify a session:
 * - Lookup: remoteAddress (ProtocolAddress)
 * - State ID: baseKey (set from PreKeyMessage.senderEphemeralKey)
 */
export interface SessionBuilderResponderInput {
  /** Local user's protocol address */
  localAddress: ProtocolAddress;
  /** Remote user's protocol address (Alice's address, used for session lookup) */
  remoteAddress: ProtocolAddress;
  /** Our identity key pair */
  identityKeyPair: IdentityKeyPair;
  /** Alice's PreKeyMessage */
  prekeyMessage: PreKeyMessage;
  /** Our signed prekey that Alice used */
  ecSignedPreKey: EcSignedPreKey;
  /** Our one-time prekey that Alice used (if any) */
  ecOneTimePreKey: EcOneTimePreKey | null;
  /** Our Kyber prekey that Alice used (if any) */
  kemLastResortPreKey: KyberPreKey | null;
  /** Our KEM one-time prekey that Alice used (if any) - for per-session post-quantum forward secrecy */
  kemOneTimePreKey: KemOneTimePreKey | null;
  /** Protocol strategy configuration (optional) */
  protocolStrategy?: ProtocolStrategyConfig;
  /** Resolved logger for session establishment */
  logger?: Required<ILogger>;
}

// ============================================================================
// SessionBuilder Result Types
// ============================================================================

/**
 * Result from building an initiator session
 */
export interface SessionBuilderInitiatorResult {
  /** The created session state */
  sessionState: SessionState;
  /** Kyber ciphertext to include in PreKeyMessage (PQXDH sessions only) */
  kyberCiphertext?: string;
  /** ID of Kyber prekey used (PQXDH sessions only) */
  kyberPreKeyId?: number;
  /**
   * Original X3DH/PQXDH shared secret (SK) for Triple Ratchet initialization.
   *
   * CRITICAL: This is the pre-ratcheted shared secret that both parties
   * must use for SPQR initialization. Alice's EC Double Ratchet uses a
   * ratcheted RK, but SPQR needs the original SK to match Bob's.
   *
   * Owned byte storage must be best-effort overwritten after use.
   */
  initialRootKeyForSPQR?: Uint8Array;
  /** Whether the session used PQXDH (post-quantum) */
  usedPQXDH: boolean;
  /** Whether the session used the explicit X3DH compatibility fallback */
  usedClassicalFallback?: boolean;
}

/**
 * Result from building a responder session
 */
export interface SessionBuilderResponderResult {
  /** The created session state */
  sessionState: SessionState;
  /** Whether the session used PQXDH (post-quantum) */
  usedPQXDH: boolean;
  /** Whether the session used the explicit X3DH compatibility fallback */
  usedClassicalFallback?: boolean;
  /**
   * Original X3DH/PQXDH shared secret (SK) for Triple Ratchet initialization.
   * Only present if the session used PQXDH.
   */
  initialRootKeyForSPQR?: Uint8Array;
}

// ============================================================================
// Internal Types (used within SessionBuilder)
// ============================================================================

/**
 * Result from key agreement modules (X3DH or PQXDH)
 */
export interface KeyAgreementResult {
  /** Shared secret from key agreement */
  sharedSecret: Uint8Array;
  /** Additional derived bytes from HKDF (96 bytes total) */
  additionalDerivedBytes?: Uint8Array;
  /** Ephemeral key pair generated during key agreement */
  ephemeralKeyPair: { publicKey: string; privateKey: string };
  /** ID of signed prekey used */
  usedSignedPreKeyId: number;
  /** ID of one-time prekey used (if any) */
  usedOneTimePreKeyId?: number;
  /** Kyber ciphertext (PQXDH sessions only) */
  kyberCiphertext?: string;
  /** ID of Kyber prekey used (if any) */
  usedKyberPreKeyId?: number;
  /** KEM one-time prekey ciphertext (if used) */
  kemOneTimePreKeyCiphertext?: string;
  /** ID of KEM one-time prekey used (if any) */
  usedKemOneTimePreKeyId?: number;
  /** Whether the session used PQXDH */
  usedPQXDH: boolean;
  /** Whether the session used the explicit X3DH compatibility fallback */
  usedClassicalFallback?: boolean;
}

/**
 * Result from responder key agreement
 */
export interface ResponderKeyAgreementResult {
  /** Shared secret from key agreement */
  sharedSecret: Uint8Array;
  /** Additional derived bytes from HKDF */
  additionalDerivedBytes?: Uint8Array;
  /** Whether the session used PQXDH */
  usedPQXDH: boolean;
  /** Whether the session used the explicit X3DH compatibility fallback */
  usedClassicalFallback?: boolean;
}

// ============================================================================
// SessionCipher Types
// ============================================================================

/**
 * Callback for establishing a session from a PreKeyMessage.
 *
 * When SessionCipher.decrypt() receives a PreKeyMessage and no session exists,
 * it calls this callback to establish the session via SessionBuilder.
 *
 * This pattern keeps session establishment logic in the manager/orchestrator
 * while allowing SessionCipher to handle the decryption flow.
 *
 * Note: no sessionId remains. A remoteAddress looks up a session.
 */
export type SessionEstablishmentCallback = (
  remoteAddress: ProtocolAddress,
  prekeyMessage: PreKeyMessage
) => Promise<SessionState>;

/**
 * Dependencies required by SessionCipher
 */
export interface SessionCipherDependencies {
  /** Key storage for loading/storing sessions */
  keyStorage: ISignalProtocolLocalStore;
  /**
   * Callback for establishing sessions from PreKeyMessages.
   * Called when decrypt() receives a PreKeyMessage and no session exists.
   */
  establishSession: SessionEstablishmentCallback;
}

/**
 * Configuration for SessionCipher
 */
export interface SessionCipherConfig {
  /**
   * Maximum number of message keys to skip in a single receiving chain.
   * Per Signal Protocol specification - prevents DoS attacks.
   * @default 1000
   */
  maxSkip?: number;

  /**
   * Protocol strategy configuration.
   *
   * The cipher does not choose protocol behavior, because session establishment
   * already did. The cipher is the layer that drives SPQR on every message, so
   * the strategy's per-message diagnostic hooks are reported from here.
   */
  protocolStrategy?: ProtocolStrategyConfig;
}
