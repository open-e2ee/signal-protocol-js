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
 * ML-KEM Braid chunk progress, for diagnostics and progress display.
 *
 * Braid mode spreads an ML-KEM key agreement across many messages: each
 * message carries one erasure-coded chunk, and an epoch closes only once
 * enough chunks have travelled in both directions. Nothing outside the braid
 * state machine can otherwise observe that, so a host that wants to show or
 * log the ratchet's progress has no other source for it.
 */
export interface BraidProgressEvent {
  /**
   * Chunks this side has carried in {@link epoch}: chunks it has emitted plus
   * chunks it has accepted.
   */
  chunksCarried: number;

  /**
   * Chunks the transfers opened in {@link epoch} account for.
   *
   * This is not a target that {@link chunksCarried} settles on. Sending
   * capacity includes roughly 30% parity beyond the chunks a peer needs to
   * reconstruct, and transfers open as the epoch advances rather than all at
   * once, so the two counts converge only loosely.
   */
  chunksRequired: number;

  /** Braid epoch the counts above belong to. */
  epoch: bigint;

  /**
   * Whether the send or receive that raised this event produced the epoch
   * secret.
   *
   * When that secret also ends the epoch, the state machine has already reset
   * its counters, so {@link chunksCarried} and {@link chunksRequired} describe
   * the epoch that has just begun rather than the one the secret closed.
   */
  emittedEpochKey: boolean;
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
   * Called after each ML-KEM Braid send or receive, in braid mode only.
   *
   * A direct-mode session never raises it, because direct mode carries no
   * chunks.
   */
  onBraidProgress?: (event: BraidProgressEvent) => void;

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
   * Clamped to the range {@link SENDER_KEY_AGE_FLOOR} to
   * {@link SENDER_KEY_AGE_CEILING}; a value outside it is treated as the bound
   * it passed, and a value that is not a positive finite number falls back to
   * the default.
   *
   * @default 1209600000
   */
  maxSenderKeyAge?: number;
}

/**
 * Hard upper bound on {@link SenderKeysConfig.maxSenderKeyAge}, in
 * milliseconds.
 *
 * A sender key is the one piece of group key material that no ratchet
 * refreshes: it advances a chain forward on every send, so it gives forward
 * secrecy against a later compromise, but a member who holds the key at time
 * T can read everything sent under it afterwards. Only rotation ends that,
 * and rotation is what this bound guarantees eventually happens. Membership
 * changes normally force it sooner; the age bound is what covers a group
 * whose membership never changes.
 *
 * Ninety days matches the ceiling the reference implementation applies to its
 * own remotely configured value. The difference here is who is being bounded:
 * the reference clamps a value it sets itself, whereas this SDK takes the
 * value from the host application, so the clamp is the only thing keeping a
 * deployment from disabling rotation outright by configuring an age no key
 * will reach.
 */
export const SENDER_KEY_AGE_CEILING = 90 * 24 * 60 * 60 * 1000;

/**
 * Hard lower bound on {@link SenderKeysConfig.maxSenderKeyAge}, in
 * milliseconds.
 *
 * Unlike the ceiling this is not a security bound — rotating sooner is
 * strictly safer — it is an availability one, and it exists because expiry is
 * enforced on a key that a *send* has to rotate and redistribute. When a key
 * expires the send path generates a new one, fans a distribution message out
 * to every other member over sequential network calls, then retries the
 * encrypt, which re-checks the age of the key it just created. If the
 * configured age is shorter than that fan-out takes, the retry finds the new
 * key already expired and the send fails permanently, having burned a rotation
 * and a message to every member on each attempt.
 *
 * An hour is well clear of that: even a group at the membership limit, with a
 * distribution message to each member, finishes its fan-out in minutes at
 * worst. It is also low enough to leave deliberately aggressive rotation
 * policies intact, which a bound measured in days would not.
 *
 * A configured age below this is treated as the bound rather than rejected,
 * because the value that reaches it is usually a unit mistake — this field is
 * milliseconds, so a host that means fourteen days and passes `14` lands here
 * — and the safe reading of "rotate far more often than I asked" is to rotate
 * as often as the implementation can actually deliver.
 */
export const SENDER_KEY_AGE_FLOOR = 60 * 60 * 1000;

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
 *
 * PQXDH section 2.2 defines this as the four PQXDH parameters - `info`,
 * `curve`, `hash`, and `pqkem` - joined by `_`, with each parameter's string
 * representation chosen by the implementer. `info` is an application
 * identifier of at least 8 bytes (section 2.1); the other three must name what
 * the implementation actually runs, which here is X25519, SHA-256, and
 * ML-KEM-1024 (FIPS 203).
 *
 * Naming a KEM that is not the one in use would derive a different shared
 * secret from an identical label, which is the one thing the info string
 * exists to prevent.
 */
export const PQXDH_INFO_DEFAULT = 'OpenE2EE_X25519_SHA-256_ML-KEM-1024';

/**
 * Default HKDF info string for X3DH session initialization.
 *
 * X3DH section 2.1 defines `info` as an ASCII string identifying the
 * application, and section 3.3 uses it as the HKDF info directly - unlike
 * PQXDH, no parameters are appended.
 */
export const X3DH_INFO_DEFAULT = 'OpenE2EE';

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
    | 'onBraidProgress'
    | 'networkConstraints'
    | 'spqrInfoStrings'
    | 'spqrLimits'
    | 'keyExchangeInfoString'
  > {
  return {
    allowClassicalFallback: config?.allowClassicalFallback ?? false,
    sckaMode: config?.sckaMode ?? 'braid',
    onProtocolSelected: config?.onProtocolSelected,
    onBraidProgress: config?.onBraidProgress,
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
