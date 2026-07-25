/**
 * Protocol strategy and profile runtime constants.
 *
 * This module is intentionally below the client API layer. Session, protocol,
 * storage, and client code all depend on these contracts, so keeping them here
 * avoids protocol internals importing from `client/config`.
 */

import type { IdentityType } from '../keys/types';

/**
 * Developer-facing post-quantum policy values.
 */
export const PostQuantumPolicy = {
  Required: 'required',
  Compatible: 'compatible',
} as const;

export type PostQuantumPolicy = (typeof PostQuantumPolicy)[keyof typeof PostQuantumPolicy];

/**
 * Developer-facing ML-KEM Braid policy values.
 */
export const BraidPolicy = {
  Required: 'required',
  Disabled: 'disabled',
} as const;

export type BraidPolicy = (typeof BraidPolicy)[keyof typeof BraidPolicy];

/**
 * Public Signal Protocol configuration.
 *
 * This keeps application code in product/security terms. Internal protocol
 * strategy details such as X3DH fallback remain below the SignalProtocolClient seam.
 */
export interface SignalProtocolConfig {
  /**
   * Post-quantum policy for session establishment.
   *
   * - `required`: require post-quantum peers; peers without PQ material fail closed.
   * - `compatible`: use post-quantum peers when available and allow classical
   *   compatibility only for peers with no PQ material at all.
   *
   * @default 'required'
   */
  postQuantum?: PostQuantumPolicy;

  /**
   * ML-KEM Braid policy for the ongoing post-quantum ratchet.
   *
   * - `required`: use the specification-defined ML-KEM Braid SPQR profile.
   * - `disabled`: explicitly use the direct ML-KEM SPQR mode instead.
   *
   * Direct mode remains post-quantum, but it is a separate SDK SPQR mode.
   * Prefer `required` unless a product-reviewed constraint needs direct mode.
   *
   * @default 'required'
   */
  braid?: BraidPolicy;
}

/**
 * Translate the public protocol config into the internal strategy shape.
 */
export function protocolConfigToStrategy(config?: SignalProtocolConfig): ProtocolStrategyConfig {
  const postQuantum = config?.postQuantum ?? PostQuantumPolicy.Required;
  const braid = config?.braid ?? BraidPolicy.Required;

  let allowClassicalFallback: boolean;
  if (postQuantum === PostQuantumPolicy.Required) {
    allowClassicalFallback = false;
  } else if (postQuantum === PostQuantumPolicy.Compatible) {
    allowClassicalFallback = true;
  } else {
    throw new Error(`Unsupported postQuantum policy: ${String(postQuantum)}`);
  }

  if (braid === BraidPolicy.Required) {
    return { allowClassicalFallback, sckaMode: 'braid' };
  }

  if (braid === BraidPolicy.Disabled) {
    return { allowClassicalFallback, sckaMode: 'direct' };
  }

  throw new Error(`Unsupported braid policy: ${String(braid)}`);
}

/**
 * Resolve public and advanced protocol configuration.
 *
 * Public `protocol` owns fallback and Braid semantics. Advanced strategy
 * options may still provide telemetry callbacks, SPQR limits, KDF strings, and
 * protocol diagnostic hooks, but they cannot also set fallback or SCKA mode behavior.
 */
export function resolveSignalProtocolStrategy(config?: {
  protocol?: SignalProtocolConfig;
  protocolStrategy?: ProtocolStrategyConfig;
}): ProtocolStrategyConfig | undefined {
  if (!config?.protocol) {
    return config?.protocolStrategy;
  }

  if (config.protocolStrategy?.allowClassicalFallback !== undefined) {
    throw new Error(
      'Do not set protocolStrategy.allowClassicalFallback with protocol.postQuantum; use protocol.postQuantum.'
    );
  }

  if (config.protocolStrategy?.sckaMode !== undefined) {
    throw new Error(
      'Do not set protocolStrategy.sckaMode with protocol.braid; use protocol.braid.'
    );
  }

  return {
    ...config.protocolStrategy,
    ...protocolConfigToStrategy(config.protocol),
  };
}

/**
 * Reason for using explicit classical compatibility fallback.
 */
export type ClassicalFallbackReason = 'remote_lacks_kem';

/**
 * Protocol selection event for analytics and debugging.
 */
export interface ProtocolSelectionEvent {
  /** Whether PQXDH (post-quantum) key exchange was used. */
  usedPQXDH: boolean;
  /** Whether Triple Ratchet (SPQR) was enabled for the session. */
  usedTripleRatchet: boolean;
  /** Whether explicit X3DH compatibility fallback was used. */
  usedClassicalFallback: boolean;
  /** Narrow reason for explicit X3DH compatibility fallback. */
  classicalFallbackReason?: ClassicalFallbackReason;
  /** Remote party's address (userId:deviceId). */
  remoteAddress: string;
  /** Timestamp of protocol selection. */
  timestamp: number;
}

/**
 * SCKA mode for SPQR key exchange.
 */
export type SCKAMode = 'direct' | 'braid';

/**
 * Network constraint hints for automatic SCKA mode selection.
 */
export interface NetworkConstraints {
  /** Maximum message size in bytes. */
  maxMessageSize?: number;
  /** Expected packet loss rate from 0.0 to 1.0. */
  expectedPacketLoss?: number;
  /** True when bandwidth is expensive or tightly constrained. */
  bandwidthConstrained?: boolean;
}

/**
 * SPQR security and performance limits.
 *
 * Defaults bound a forward jump to 25,000 and retained out-of-order keys to
 * 2,000.
 */
export interface SPQRLimits {
  /** Maximum forward jump in message numbers. @default 25000 */
  maxMessageJump?: number;
  /** Maximum out-of-order keys to store. @default 2000 */
  maxOutOfOrderKeys?: number;
}

/**
 * SPQR HKDF info string configuration.
 *
 * The default chain-start value deliberately contains two spaces before
 * "Start". Changing that byte sequence changes derived keys.
 */
export interface SPQRInfoStrings {
  /** Prefix for all SPQR chain info strings. */
  prefix?: string;
  /** Chain initialization info string. */
  chainStart?: string;
  /** Epoch advancement info string. */
  chainAddEpoch?: string;
  /** Per-message advancement info string. */
  chainNext?: string;
}

/**
 * Protocol strategy configuration for PQXDH and SPQR.
 */
export interface ProtocolStrategyConfig {
  /**
   * Allow explicit X3DH compatibility fallback for peers that advertise no
   * KEM/PQ material at all.
   *
   * This does not allow downgrade after malformed KEM metadata, failed PQXDH
   * processing, or missing local KEM prekeys for incoming PQXDH messages.
   *
   * @default false
   */
  allowClassicalFallback?: boolean;

  /**
   * SCKA mode for SPQR key exchange.
   *
   * @default 'braid'
   */
  sckaMode?: SCKAMode;

  /**
   * Future automatic SCKA mode selection hints.
   */
  networkConstraints?: NetworkConstraints;

  /**
   * Called after key exchange completes, before the first message is encrypted.
   */
  onProtocolSelected?: (event: ProtocolSelectionEvent) => void;

  /**
   * Custom SPQR HKDF info strings.
   */
  spqrInfoStrings?: SPQRInfoStrings;

  /**
   * Override HKDF info string for both X3DH and PQXDH key derivation.
   */
  keyExchangeInfoString?: string;

  /**
   * SPQR security and performance limits.
   */
  spqrLimits?: SPQRLimits;
}

/**
 * Sender Keys (group messaging) configuration options.
 */
export interface SenderKeysConfig {
  /**
   * HKDF info string for message key derivation.
   *
   * @default "WhisperGroup"
   */
  hkdfInfoString?: string;

  /**
   * Maximum chain advancement per message.
   *
   * @default 25000
   */
  maxChainAdvance?: number;

  /**
   * Maximum skipped message keys to store per sender.
   *
   * @default 2000
   */
  maxSkippedKeys?: number;

  /**
   * Maximum age for locally generated sender keys before rotation.
   *
   * @default 1209600000
   */
  maxSenderKeyAge?: number;
}

/**
 * Default values for Sender Keys configuration.
 */
export const SENDER_KEYS_DEFAULTS = {
  hkdfInfoString: 'WhisperGroup',
  maxChainAdvance: 25000,
  maxSkippedKeys: 2000,
  maxSenderKeyAge: 14 * 24 * 60 * 60 * 1000,
} as const;

/**
 * Maximum number of sender key states per sender.
 */
export const MAX_SENDER_KEY_STATES = 5;

/**
 * Result counts from culling replaced prekeys.
 */
export interface ReplacedPreKeyCullResult {
  ecSignedPreKeys: number;
  kyberPreKeys: number;
  ecOneTimePreKeys: number;
  kyberOneTimePreKeys: number;
}

/**
 * Result counts from culling replaced one-time prekeys.
 */
export interface ReplacedOneTimePreKeyCullResult {
  ecOneTimePreKeys: number;
  kyberOneTimePreKeys: number;
}

/**
 * App-provided persistence helpers for prekey replacement bookkeeping.
 *
 * The Signal Protocol SDK owns rotation semantics; concrete storage adapters own
 * persistence.
 */
export interface PreKeyMaintenanceStore {
  /**
   * Mark active EC one-time prekeys as replaced before generating a fresh batch.
   */
  markEcOneTimePreKeysReplaced(identityType?: IdentityType): Promise<void>;

  /**
   * Mark active Kyber one-time prekeys as replaced before generating a fresh batch.
   */
  markKyberOneTimePreKeysReplaced(identityType?: IdentityType): Promise<void>;

  /**
   * Delete replaced one-time prekeys that have exceeded the grace period.
   */
  cullReplacedOneTimePreKeys(
    maxReplacedAgeMs: number,
    identityType?: IdentityType
  ): Promise<ReplacedOneTimePreKeyCullResult>;

  /**
   * Delete all replaced prekeys that have exceeded the grace period.
   */
  cullReplacedPreKeys(maxReplacedAgeMs: number): Promise<ReplacedPreKeyCullResult>;
}

/**
 * Default key refresh interval: 2 days.
 */
export const KEY_REFRESH_INTERVAL_MS_DEFAULT = 2 * 24 * 60 * 60 * 1000;

/**
 * Maximum allowed prekey age: 14 days.
 */
export const MAX_PREKEY_AGE_MS_DEFAULT = 14 * 24 * 60 * 60 * 1000;

/**
 * Default prekey check throttle interval: 12 hours.
 */
export const PREKEY_CHECK_THROTTLE_MS_DEFAULT = 12 * 60 * 60 * 1000;

/**
 * Maximum age for unacknowledged sessions: 30 days.
 */
export const MAX_UNACKNOWLEDGED_SESSION_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Maximum archived session states per address.
 */
export const ARCHIVED_STATES_MAX_LENGTH = 40;

/**
 * Default HKDF info string for PQXDH session initialization.
 */
export const PQXDH_INFO_DEFAULT = 'WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024';

/**
 * Default HKDF info string for X3DH session initialization.
 */
export const X3DH_INFO_DEFAULT = 'WhisperText';

/**
 * Validation result for protocol strategy configuration.
 */
export interface ProtocolStrategyValidation {
  /** Whether the configuration is valid. */
  valid: boolean;
  /** Warning messages for valid but suboptimal configurations. */
  warnings: string[];
  /** Error messages for invalid configurations. */
  errors: string[];
}

/**
 * Validate protocol strategy configuration.
 */
export function validateProtocolStrategy(
  config?: ProtocolStrategyConfig
): ProtocolStrategyValidation {
  const warnings: string[] = [];
  const errors: string[] = [];

  if (!config) {
    return { valid: true, warnings, errors };
  }

  if (config.allowClassicalFallback) {
    warnings.push(
      'Classical compatibility fallback is enabled; it is used only for peers with no KEM material.'
    );
  }

  if (config.sckaMode === 'direct') {
    warnings.push(
      'Direct SPQR SCKA is non-canonical; use it only for protocol tests or product-reviewed constraints.'
    );
  }

  return {
    valid: errors.length === 0,
    warnings,
    errors,
  };
}

/**
 * Apply default values to protocol strategy configuration.
 */
export function applyProtocolStrategyDefaults(
  config?: ProtocolStrategyConfig
): Required<Pick<ProtocolStrategyConfig, 'sckaMode' | 'allowClassicalFallback'>> &
  Pick<
    ProtocolStrategyConfig,
    | 'onProtocolSelected'
    | 'networkConstraints'
    | 'spqrInfoStrings'
    | 'spqrLimits'
    | 'keyExchangeInfoString'
  > {
  return {
    allowClassicalFallback: config?.allowClassicalFallback ?? false,
    sckaMode: config?.sckaMode ?? 'braid',
    onProtocolSelected: config?.onProtocolSelected,
    networkConstraints: config?.networkConstraints,
    spqrInfoStrings: config?.spqrInfoStrings,
    spqrLimits: config?.spqrLimits,
    keyExchangeInfoString: config?.keyExchangeInfoString,
  };
}

/**
 * Resolved SPQR limits with profile defaults applied.
 */
export interface ResolvedSPQRLimits {
  /** Max forward jump in message numbers. @default 25000 */
  maxMessageJump: number;
  /** Max out-of-order keys to store. @default 2000 */
  maxOutOfOrderKeys: number;
}

/**
 * profile defaults for SPQR limits.
 */
export const SPQR_LIMITS_DEFAULTS: ResolvedSPQRLimits = {
  maxMessageJump: 25000,
  maxOutOfOrderKeys: 2000,
};

/**
 * Resolve SPQR limits with profile defaults.
 */
export function resolveSPQRLimits(limits?: SPQRLimits): ResolvedSPQRLimits {
  return {
    maxMessageJump: limits?.maxMessageJump ?? SPQR_LIMITS_DEFAULTS.maxMessageJump,
    maxOutOfOrderKeys: limits?.maxOutOfOrderKeys ?? SPQR_LIMITS_DEFAULTS.maxOutOfOrderKeys,
  };
}

/**
 * Resolve SCKA mode based on explicit configuration.
 */
export function resolveSCKAMode(config?: ProtocolStrategyConfig): SCKAMode {
  return config?.sckaMode ?? 'braid';
}

/**
 * Resolved key exchange info strings.
 */
export interface ResolvedKeyExchangeInfoStrings {
  /** PQXDH info string. */
  pqxdh: string;
  /** X3DH info string. */
  x3dh: string;
}

/**
 * Resolve key exchange info strings.
 */
export function resolveKeyExchangeInfoStrings(override?: string): ResolvedKeyExchangeInfoStrings {
  if (override) {
    return { pqxdh: override, x3dh: override };
  }
  return {
    pqxdh: PQXDH_INFO_DEFAULT,
    x3dh: X3DH_INFO_DEFAULT,
  };
}
