/**
 * Protocol strategy and profile runtime constants.
 *
 * This module is intentionally below the client API layer. Session, protocol,
 * storage, and client code all depend on these contracts, so keeping them here
 * avoids protocol internals importing from `client/config`.
 */

import type { IdentityType } from '../keys/types';
import type { LocalStoreAtRest, LocalStoreKeyCustody } from './api';

/**
 * Developer-facing post-quantum policy values.
 */
export const PostQuantumPolicy = {
  Required: 'required',
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
 * strategy details remain below the SignalProtocolClient seam.
 */
export interface SignalProtocolConfig {
  /**
   * Post-quantum policy for session establishment.
   *
   * `required` is the only value. Every new session uses PQXDH, and a peer
   * without ML-KEM prekeys fails closed with `PQXDH_REQUIRED`.
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

  /**
   * Policy for the content that a sender keeps to answer a retry request.
   *
   * A device that cannot decrypt a message asks the sender for it again. To
   * answer, the sender keeps the plaintext of each resendable message in its
   * local store until the recipient device confirms it or the retention
   * ends. This policy decides whether the local store may hold that
   * plaintext. The client reads it at creation and shows the decision in
   * `contentRecoveryStatus`.
   *
   * @default { mode: 'require-protected' }
   */
  contentRecovery?: ContentRecoveryPolicy;

  /**
   * Policy for received content that waits on this device.
   *
   * The client stores decrypted content before it acknowledges the Relay
   * message, then processes it. Content waits when its group state is not
   * current, when its delivery receipt is due, or until the application
   * completes a helper receive. This policy bounds the queue. Content that
   * waits 30 days from its first durable admission on this device expires,
   * and the client runs `onReceiveExpired` and drops it. Content whose
   * delivery receipt is due completes with no receipt and no
   * `onReceiveExpired` report at that age, or 1 day after the receipt
   * became due if that is earlier. The age uses the wall clock: a forward
   * clock jump can expire content early. Retention cannot recover content
   * whose keys or sender content are gone. No setting changes this age.
   *
   * @default { maxItems: 3000, maxBytes: 786432000, blockedGroupShare: 0.25 }
   */
  receiveQueue?: ReceiveQueuePolicy;
}

/** The receive queue policy of a client. */
export interface ReceiveQueuePolicy {
  /**
   * The most receive records that the queue holds. At the bound, the client
   * decrypts nothing more and does not acknowledge the message, so the
   * Relay keeps it. A message that the Relay keeps expires at the TTL of
   * the Relay project, and no local hook reports that expiry. While the
   * mailbox of the device is full, the Relay refuses a new message to it
   * with `MAILBOX_FULL` to its sender. The value is provisional until a
   * measurement sets it.
   * Two processes over one store, such as two tabs, can each pass the check
   * and overshoot it.
   *
   * @default 3000
   */
  maxItems?: number;

  /**
   * The most plaintext bytes that the queue holds. It acts as `maxItems`.
   *
   * @default 786432000 (750 MiB)
   */
  maxBytes?: number;

  /**
   * The part of `maxItems` and `maxBytes` that the waiting records of one
   * group can fill. A sender-key message of a group at its part is not
   * decrypted, so other conversations keep room. Pairwise group content
   * counts toward its group after decrypt. The value must be above 0 and at
   * most 1.
   *
   * @default 0.25
   */
  blockedGroupShare?: number;

  /**
   * The longest time, in milliseconds, that a receive pass waits for one
   * hook, such as `onMessageDecrypted`. At the bound, the client logs `RECEIVE_HOOK_TIMEOUT` and stops waiting for
   * the call. A timeout of `onMessageDecrypted` or `onDelivered` counts as
   * one failed attempt, so the content runs again after the backoff. A
   * timeout of another hook ends that call, and the pass continues. The
   * client ignores a result that the call gives after the bound. The value
   * must be a positive integer of at most 2147483647 ms.
   *
   * @default 120000 (2 minutes)
   */
  receiveHookTimeoutMs?: number;
}

/**
 * Which local store protection lets the client keep resendable content.
 *
 * - `require-protected`: keep it only when the store is encrypted and its
 *   key is in an operating system keychain or a declared application vault.
 * - `allow-co-located-key`: also keep it when the key is in storage that
 *   the data shares, such as the same browser origin. Use it only after a
 *   product review accepts that custody.
 * - `off`: never keep it.
 */
export type ContentRecoveryMode = 'require-protected' | 'allow-co-located-key' | 'off';

/** The content recovery policy of a client. */
export interface ContentRecoveryPolicy {
  /** @default 'require-protected' */
  mode?: ContentRecoveryMode;

  /**
   * How long the sender keeps resendable content, in milliseconds, from the
   * time it first stored the content. A retry does not extend it. The value
   * must be a positive integer of at most 30 days.
   *
   * @default 1209600000 (14 days)
   */
  retentionMs?: number;

  /**
   * Answer whether a user is a current member of an ad hoc group. The
   * sender asks it before it gives logged group content to a device again.
   * A managed group is checked against its verified group state instead.
   * The hook gets the prefixed group ID that `createGroupId` makes. Without
   * this hook, the sender gives no content again for an ad hoc group.
   * `contentRecoveryStatus.groupMembershipSource` names the source that the
   * client has.
   */
  isCurrentMember?: (groupId: string, userId: string) => Promise<boolean>;
}

/**
 * How well a local store protects resendable content.
 *
 * - `protected`: the store is encrypted, and its key is in an operating
 *   system keychain or a declared application vault.
 * - `co-located`: the store is encrypted, and its key is in storage that the
 *   data shares, such as the same browser origin. This is weaker key
 *   custody, not missing encryption.
 * - `none`: the store has no encryption or no key.
 */
export type StorageProtectionLevel = 'protected' | 'co-located' | 'none';

/**
 * Where the client finds whether a user is a current member of a group,
 * before it gives group content to a device again.
 *
 * - `managed`: `groups` with `resolveAciBytesByUserIds`. The client checks
 *   a managed group against its verified group state. When
 *   `isCurrentMember` is also set, it answers for an ad hoc group.
 * - `hook`: only `protocol.contentRecovery.isCurrentMember`. It answers for
 *   an ad hoc group. A resend for a managed group is refused.
 * - `none`: no source. Each group resend is refused. A direct message
 *   resend needs no source.
 */
export type GroupMembershipSource = 'managed' | 'hook' | 'none';

/** Why the client keeps no resendable content. */
export type ContentRecoveryDisabledReason =
  | 'policy-off'
  | 'co-located-key-not-allowed'
  | 'unprotected-store';

/**
 * The content recovery decision of a client. The client makes it at
 * creation from the protection that the local store declares and from
 * `protocol.contentRecovery`. It does not change while the client runs.
 *
 * When `enabled` is false, the client keeps no resendable content. A retry
 * request for a direct message then resets the session with no content, and
 * a group message is sent with the `Default` content hint instead of
 * `Resendable`.
 */
export interface ContentRecoveryStatus {
  readonly enabled: boolean;
  readonly level: StorageProtectionLevel;
  readonly mode: ContentRecoveryMode;
  readonly atRest: LocalStoreAtRest;
  readonly keyCustody: LocalStoreKeyCustody;
  /** Set only when `enabled` is false. */
  readonly reason?: ContentRecoveryDisabledReason;
  /** The group membership source that a group resend uses. */
  readonly groupMembershipSource: GroupMembershipSource;
}

/**
 * Translate the public protocol config into the internal strategy shape.
 */
export function protocolConfigToStrategy(config?: SignalProtocolConfig): ProtocolStrategyConfig {
  const postQuantum = config?.postQuantum ?? PostQuantumPolicy.Required;
  const braid = config?.braid ?? BraidPolicy.Required;

  if (postQuantum !== PostQuantumPolicy.Required) {
    throw new Error(`Unsupported postQuantum policy: ${String(postQuantum)}`);
  }

  if (braid === BraidPolicy.Required) {
    return { sckaMode: 'braid' };
  }

  if (braid === BraidPolicy.Disabled) {
    return { sckaMode: 'direct' };
  }

  throw new Error(`Unsupported braid policy: ${String(braid)}`);
}

/**
 * Resolve public and advanced protocol configuration.
 *
 * Public `protocol` owns the post-quantum and Braid semantics. Advanced
 * strategy options may still provide telemetry callbacks, SPQR limits, KDF
 * strings, and protocol diagnostic hooks. They cannot also set the SCKA mode.
 */
export function resolveSignalProtocolStrategy(config?: {
  protocol?: SignalProtocolConfig;
  protocolStrategy?: ProtocolStrategyConfig;
}): ProtocolStrategyConfig | undefined {
  if (!config?.protocol || isPolicyOnly(config.protocol)) {
    return config?.protocolStrategy;
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

/** The `protocol` keys that set a client policy, not a protocol strategy. */
const POLICY_KEYS: readonly string[] = ['contentRecovery', 'receiveQueue'];

/**
 * The content recovery and receive queue policies are not a protocol
 * strategy. A `protocol` object that sets only those policies leaves the
 * advanced strategy alone.
 */
function isPolicyOnly(protocol: SignalProtocolConfig): boolean {
  const keys = Object.keys(protocol);
  return keys.length > 0 && keys.every((key) => POLICY_KEYS.includes(key));
}

/**
 * Protocol selection event for analytics and debugging.
 */
export interface ProtocolSelectionEvent {
  /** Whether PQXDH (post-quantum) key exchange was used. */
  usedPQXDH: boolean;
  /** Whether Triple Ratchet (SPQR) was enabled for the session. */
  usedTripleRatchet: boolean;
  /** Remote party's address (userId:deviceId). */
  remoteAddress: string;
  /** Timestamp of protocol selection. */
  timestamp: number;
}

/**
 * ML-KEM Braid chunk progress, for diagnostics and progress display.
 *
 * Braid mode spreads an ML-KEM key agreement across many messages. Each
 * message carries one erasure-coded chunk, and an epoch closes only once
 * enough chunks have traveled in both directions. Nothing outside the braid
 * state machine can otherwise observe that. A host that wants to show or log
 * the ratchet's progress has no other source for it.
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
   * reconstruct. Transfers also open as the epoch advances rather than all at
   * once. The two counts therefore converge only loosely.
   */
  chunksRequired: number;

  /** Braid epoch the counts above belong to. */
  epoch: bigint;

  /**
   * Whether the send or receive that raised this event produced the epoch
   * secret.
   *
   * When that secret also ends the epoch, the state machine has already reset
   * its counters. The counters {@link chunksCarried} and
   * {@link chunksRequired} then describe the epoch that has just begun rather
   * than the one the secret closed.
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
 * 2,000 in each epoch.
 */
export interface SPQRLimits {
  /** Maximum forward jump in message numbers. @default 25000 */
  maxMessageJump?: number;
  /**
   * Maximum out-of-order keys that each epoch keeps. A key more than this
   * count behind the newest received index is refused. @default 2000
   */
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
   * Called after key exchange completes, before the client encrypts the first message.
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
   * Override HKDF info string for PQXDH key derivation.
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
   * {@link SENDER_KEY_AGE_CEILING}. A value outside it becomes the bound it
   * passed. A value that is not a positive finite number falls back
   * to the default.
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
 * refreshes. It advances a chain forward on every send, so it gives forward
 * secrecy against a later compromise. A member who holds the key at time T
 * can still read everything sent under it afterwards. Only rotation ends that,
 * and rotation is what this bound guarantees eventually happens. Membership
 * changes normally force it sooner. The age bound is what covers a group
 * whose membership never changes.
 *
 * Ninety days matches the ceiling the reference implementation applies to its
 * own remotely configured value. The difference here is whose value the bound covers.
 * The reference clamps a value it sets itself, whereas this SDK takes the
 * value from the host application. The clamp is therefore the only thing that
 * keeps a deployment from disabling rotation outright by configuring an age
 * no key will reach.
 */
export const SENDER_KEY_AGE_CEILING = 90 * 24 * 60 * 60 * 1000;

/**
 * Hard lower bound on {@link SenderKeysConfig.maxSenderKeyAge}, in
 * milliseconds.
 *
 * Unlike the ceiling this is not a security bound, because rotating sooner is
 * strictly safer. It is an availability one, and it exists because the expiry
 * falls on a key that a *send* has to rotate and redistribute.
 *
 * When a key expires the send path generates a new one. It fans a
 * distribution message out to every other member over sequential network
 * calls, then retries the encrypt. That retry re-checks the age of the key it
 * just created. If the configured age is shorter than the fan-out takes, the
 * retry finds the new key already expired and the send fails permanently.
 * Each attempt burns a rotation and a message to every member.
 *
 * An hour is well clear of that. Even a group at the membership limit, with a
 * distribution message to each member, finishes its fan-out in minutes at
 * worst. It is also low enough to leave deliberately aggressive rotation
 * policies intact, which a bound measured in days would not.
 *
 * A configured age below this becomes the bound, and does not raise an error.
 * The value that reaches it is usually a unit mistake. This field is
 * milliseconds, so a host that means fourteen days and passes `14` lands
 * here. The safe reading of "rotate far more often than I asked" is to rotate
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
 * The Signal Protocol SDK owns rotation semantics. Concrete storage adapters own
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
   * Delete replaced one-time prekeys past the grace period.
   */
  cullReplacedOneTimePreKeys(
    maxReplacedAgeMs: number,
    identityType?: IdentityType
  ): Promise<ReplacedOneTimePreKeyCullResult>;

  /**
   * Delete all replaced prekeys past the grace period.
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
 * PQXDH section 2.2 defines this as the four PQXDH parameters joined by `_`,
 * which are `info`, `curve`, `hash`, and `pqkem`. Each parameter's string
 * representation is chosen by the implementer. The `info` parameter is an
 * application identifier of at least 8 bytes (section 2.1). The other three
 * must name what the implementation actually runs, which here is X25519,
 * SHA-256, and ML-KEM-1024 (FIPS 203).
 *
 * Naming a KEM that is not the one in use would derive a different shared
 * secret from an identical label. Preventing that is what the info string
 * exists for.
 */
export const PQXDH_INFO_DEFAULT = 'OpenE2EE_X25519_SHA-256_ML-KEM-1024';

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
): Required<Pick<ProtocolStrategyConfig, 'sckaMode'>> &
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
  /**
   * Max out-of-order keys that each epoch keeps. A key more than this count
   * behind the newest received index is refused. @default 2000
   */
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
}

/**
 * Resolve key exchange info strings.
 */
export function resolveKeyExchangeInfoStrings(override?: string): ResolvedKeyExchangeInfoStrings {
  return { pqxdh: override || PQXDH_INFO_DEFAULT };
}
