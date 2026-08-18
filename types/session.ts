/**
 * Session type definitions for Signal Protocol Double Ratchet and Triple Ratchet
 */

import { ProtocolAddress } from './address';
import type {
  CompositeIdentityV1,
  IdentityKeyPair,
  IdentityType,
  PublicKey,
  PrivateKey,
} from '../keys';
import {
  compositeIdentitiesEqual,
  createCompositeIdentityV1,
  encodeCompositeIdentityV1,
} from '../keys/identity';
import type { Base64 } from './utils';
import { asBase64 } from './utils';
import { DEFAULT_SESAME_CONFIG } from '../internal/sesame/types';
import type { VersionNegotiationState } from '../internal/protocol/version';
import type { ResolvedSPQRInfoStrings } from '../internal/crypto';
import type {
  MLKEMBraidAgentState,
  MLKEMBraidMessage,
} from '../internal/protocol/spqr/ml-kem-braid/types';
import type { ResolvedSPQRLimits, SCKAMode } from './protocol-config';

// ============================================================================
// Session State Version
// ============================================================================

/**
 * Persisted record version for the composite-identity session profile.
 *
 * Version 4 is a deliberate pre-1.0 format break. Version 3 records did not
 * bind the ACI/PNI namespaces of both endpoint identity tuples. Such records
 * must be reset, never migrated or interpreted as version 4.
 */
export const CURRENT_SESSION_RECORD_VERSION = 4;

// ============================================================================
// Receiver Chain Types (Signal Protocol storage.proto compatible)
// ============================================================================

/**
 * Stored message key for out-of-order decryption.
 *
 * Field names and units are stable so a future protobuf codec can preserve the
 * persisted meaning.
 *
 */
export {};
export interface StoredMessageKey {
  /** Message index in chain (proto: index, field 1) */
  index: number;

  /**
   * 32-byte seed for key derivation (proto: seed, field 2).
   *
   * Callers derive the full message key (cipher_key, mac_key, iv) from the seed
   * on demand. This is 3x more storage efficient than storing pre-computed keys.
   */
  seed: Base64;

  /**
   * Storage timestamp for FIFO eviction.
   *
   * Per Signal Protocol Section 8.4:
   * "A recommended policy is to delete message keys more than one week old"
   */
  timestamp: number;
}

/**
 * Receiver chain with skipped message keys.
 *
 * The SDK maintains up to MAX_RECEIVER_CHAINS (5) receiver chains
 * to handle out-of-order DH ratchets.
 *
 */
export interface ReceiverChain {
  /**
   * Sender's ratchet public key (proto: sender_ratchet_key, field 1).
   *
   * Identifies which DH ratchet epoch this chain belongs to.
   */
  senderRatchetKey: Base64;

  /**
   * Chain key for deriving more message keys (proto: chain_key, field 2).
   *
   * May be null if chain key is no longer needed (all expected messages received).
   */
  chainKey: Base64 | null;

  /**
   * Skipped message keys (proto: message_keys, field 3).
   *
   * This array holds keys for messages that arrive out of order. When the
   * skipped message arrives, decryption consumes (removes) its key.
   */
  messageKeys: StoredMessageKey[];
}

/**
 * Signal Protocol session state (Full Double Ratchet)
 *
 * Implements the complete Double Ratchet algorithm with:
 * - DH ratchet (periodic Diffie-Hellman key exchange)
 * - Symmetric ratchet (chain key updates)
 * - Out-of-order message handling
 * - Break-in recovery and future secrecy
 *
 * State variable names follow Signal Protocol specification exactly:
 * - DHs, DHr: DH ratchet keys
 * - RK: Root Key
 * - CKs, CKr: Chain Keys (sending/receiving)
 * - Ns, Nr, PN: Message counters
 * - receiverChains: Skipped message keys (protobuf-compatible format)
 *
 * Note: This uses Section 3 variant (plaintext headers + MAC) not Section 4
 * (header encryption). Header keys (HKs, HKr, NHKs, NHKr) are not used.
 */
export interface SessionState {
  /**
   * Session state identifier - initiator's ephemeral public key (EKA).
   *
   * The initiator's ephemeral public key is the unique identifier for this
   * session state. This field takes the name "baseKey" because:
   * - "ephemeral" describes the key's LIFECYCLE (temporary, single-use)
   * - "base" describes the key's ROLE (foundation for SK derivation in X3DH/PQXDH)
   *
   * For initiator (Alice): Set to ephemeralKeyPair.publicKey from X3DH/PQXDH
   * For responder (Bob): Set to senderEphemeralKey from PreKeyMessage
   *
   * CRITICAL: This is different from sessionId/ProtocolAddress lookup.
   * A ProtocolAddress (userId:deviceId) LOOKS UP a session, but a baseKey
   * (ephemeral public key) IDENTIFIES a session STATE.
   *
   */
  baseKey: Base64;

  // Address information
  localAddress: ProtocolAddress; // Our address (userId + deviceId)
  remoteAddress: ProtocolAddress; // Remote party's address (userId + deviceId)

  // Convenience fields (derived from addresses for easy access)
  localDeviceId: number; // Our device ID (same as localAddress.deviceId)
  remoteDeviceId: number; // Remote device ID (same as remoteAddress.deviceId)

  // Registration IDs for session reset detection
  /**
   * Our registration ID (from our IdentityKeyPair).
   *
   * Generated once per app install. Detects a reinstall on our side.
   */
  localRegistrationId: number;

  /**
   * Remote party's registration ID (from their PreKeyBundle).
   *
   * If this changes, they reinstalled their app and we should
   * archive the old session and establish a new one.
   */
  remoteRegistrationId: number;

  // DH ratchet keys (spec names)
  DHs: { publicKey: PublicKey; privateKey: PrivateKey } | null; // Our current DH key pair
  DHr: PublicKey | undefined; // Remote party's current DH public key (undefined for lazy init)

  // Root key for deriving new chain keys (spec name)
  RK: Base64; // Root Key

  // Chain keys - symmetric ratchet (spec names).
  // Per Signal Protocol Section 3.3, the responder's chain keys are undefined
  // until the first DHRatchet.
  CKs: Base64 | undefined; // Sending Chain Key (undefined for lazy init).
  CKr: Base64 | undefined; // Receiving Chain Key (undefined for lazy init).

  // Message counters (spec names).
  Ns: number; // Number of messages sent in current sending chain.
  Nr: number; // Number of messages received in current receiving chain.
  PN: number; // Previous chain length (sent in header).

  /**
   * Receiver chains with skipped message keys (v3 format).
   *
   * This implements the spec's MKSKIPPED dictionary:
   * > "MKSKIPPED: Dictionary of skipped-over message keys, indexed by ratchet
   * > public key and message number. Raises an exception if too many elements
   * > are stored."
   *
   * Signal Protocol Section 3.5: Store skipped message keys indexed by
   * (ratchetKey, counter) for out-of-order message decryption.
   *
   * This nested structure provides bounded skipped-key storage:
   * - Up to MAX_RECEIVER_CHAINS (5) chains stored
   * - Each chain indexed by sender's ratchet public key
   * - Each chain contains up to MAX_MESSAGE_KEYS (2000 total) message keys
   *
   * @see Signal Protocol Double Ratchet Section 3.1 (state.MKSKIPPED)
   */
  receiverChains: ReceiverChain[];

  /**
   * Processed receiving chains for replay detection.
   *
   * When a DH ratchet occurs, we store the old DHr and its final Nr value
   * to detect replay attacks. If a message arrives with an old DHr:
   * - If in receiverChains: decrypt (out-of-order message)
   * - If in processedChains but not receiverChains: replay attack (already processed)
   * - If not in either: new chain (run the DH ratchet)
   *
   * Key: DHr (Base64 DH public key)
   * Value: { lastNr: number, timestamp: number }
   */
  processedChains?: Record<string, { lastNr: number; timestamp: number }>;

  // X3DH prekey tracking (for PreKeyMessage - only set for initiator).
  /** Explicit remote identity namespace included in authenticated PreKeyMessages. */
  recipientIdentityType?: IdentityType;
  usedSignedPreKeyId?: number; // ID of remote party's signed prekey used in X3DH.
  usedOneTimePreKeyId?: number; // ID of remote party's one-time prekey used in X3DH (if available).
  usedKyberPreKeyId?: number; // ID of remote party's Kyber prekey used in PQXDH (if available).
  usedKemOneTimePreKeyId?: number; // ID of remote party's one-time KEM prekey used in PQXDH (if available).

  /**
   * Prekey IDs pending deletion after first successful decryption.
   *
   * The client deletes one-time prekeys after decryption succeeds, not after session
   * establishment. This prevents
   * irrecoverable failure if the inner message arrives corrupted (the sender can
   * retry with the same prekey).
   *
   * Set during performX3DHResponder() and cleared after the first successful
   * decrypt in SessionCipher.
   */
  pendingPreKeyDeletion?: {
    oneTimePreKeyId?: number;
    kemOneTimePreKeyId?: number;
    /** Identity type the prekeys belong to (for correct scoped deletion) */
    identityType: 'aci' | 'pni';
  };

  // PQXDH temporary data for unacknowledged PreKeyMessages.
  // Retained until the responder authenticates a reply, then cleared.
  kyberCiphertext?: Base64; // Kyber ciphertext to send in PreKeyMessage (initiator only)
  kemOneTimePreKeyCiphertext?: Base64; // KEM one-time prekey ciphertext (initiator only)

  // Session role tracking (for PreKeyMessage pattern)
  isInitiator?: boolean; // True if this party initiated the session (sent first PreKeyMessage)

  /**
   * Whether this session still needs to send PreKeyMessages.
   *
   * Set to true when the client creates the session as initiator. Remains true
   * until the first message arrives from the responder, which proves the
   * responder successfully processed the PreKeyMessage.
   *
   * If the first PreKeyMessage is lost, subsequent messages
   * are still sent as PreKeyMessages so the responder can establish the session.
   *
   * @default undefined (treated as false for responder sessions)
   */
  unacknowledgedPreKeyMessage?: boolean;

  /**
   * Whether we received at least one message in this session.
   *
   * Unacknowledged PreKey sessions (where the initiator has not received a
   * reply) expire after 30 days (MAX_UNACKNOWLEDGED_SESSION_AGE).
   *
   * @default false for initiator sessions, true for responder sessions
   */
  hasReceivedMessage?: boolean;

  // Post-Quantum Sparse Refresh (SPQR / Triple Ratchet)
  // Per the SPQR specification: ML-KEM keys refreshed ~every 50 messages (or within 1 week)
  // @see https://signal.org/blog/spqr/
  // @see DEFAULT_RATCHET_CONFIG.kyberRefreshInterval
  kyberKeys?: {
    publicKey: Base64; // Remote party's Kyber public key, for refresh operations
    lastRefreshNs: number; // Value of Ns when Kyber was last refreshed
  } | null;
  lastKyberUpdate?: number | null; // Timestamp of last Kyber refresh (for 1-week fallback)

  // Non-spec metadata (camelCase for implementation details)
  identityKeyPair: IdentityKeyPair;
  /** Canonical identities bound into transcript and message authentication. */
  localIdentity: CompositeIdentityV1;
  remoteIdentity: CompositeIdentityV1;
  /** Identity namespaces are part of the session trust binding. */
  localIdentityType: IdentityType;
  remoteIdentityType: IdentityType;
  kyberSecretKey?: Base64;
  createdAt: number;
  lastUsedAt: number;

  // Triple Ratchet state - set for established PQXDH sessions.
  // When present, combines contributions from:
  // - EC Double Ratchet (existing SessionState fields above = ec_state)
  // - Sparse Post-Quantum Ratchet (new SPQR state below = spqrState)
  tripleRatchet?: TripleRatchetState | null;
}

// ============================================================================
// SessionState Helper Functions
// ============================================================================

/**
 * Helper functions for working with SessionState.
 *
 * Following the same namespace pattern as SessionRecord and ProtocolAddress.
 */
export namespace SessionState {
  /**
   * Returns the session identifier for display and logging.
   *
   * This is the SESAME SessionID concept - a human-readable string
   * that identifies which remote device this session is with.
   * Format: "userId:deviceId" (equals ProtocolAddress.toString(remoteAddress))
   *
   * Note: For cryptographic state identification, use `baseKey` instead.
   * The baseKey distinguishes multiple session instances with the same device.
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  export function getSessionId(session: SessionState): string {
    return ProtocolAddress.toString(session.remoteAddress);
  }
}

// ============================================================================
// Triple Ratchet Type Definitions (Signal Protocol Section 6)
// ============================================================================

/**
 * KDF Chain state for SPQR.
 *
 * Each epoch maintains separate KDF chains for sending and receiving.
 * KDF chains derive message keys from a chain key using KDF_CK().
 *
 * Signal Protocol Section 5.3:
 * "Each epoch e has two KDF chains: one for sending and one for receiving"
 */
export interface KDFChain {
  /** Chain key (derives message keys) */
  CK: Base64;
  /** Message counter (number of keys derived from this chain) */
  N: number;
}

/**
 * ML-KEM Braid state for continuous key agreement.
 *
 * Signal Protocol Section 5 (ML-KEM Braid):
 * The ML-KEM Braid provides continuous post-quantum key agreement by
 * maintaining alternating send/receive Kyber key pairs across epochs.
 *
 * Intended properties are conditional on authenticated establishment, correct
 * state handling, uncompromised refresh entropy, and the underlying primitive
 * assumptions. See docs/SECURITY.md.
 */
export interface SCKAState {
  /** Current epoch number (increments with each DH ratchet) */
  epoch: number;

  /** Which way messages flow ('A2B' = Alice to Bob, 'B2A' = Bob to Alice) */
  direction: 'A2B' | 'B2A';

  /** Our current Kyber private key (for receiving) */
  ourKyberPrivateKey: Base64 | null;

  /** Remote party's current Kyber public key (for sending) */
  theirKyberPublicKey: Base64 | null;

  /** Timestamp of last Kyber key refresh (for time-based rotation) */
  lastRefreshTimestamp: number;

  /** Message counter at last Kyber refresh (for message-count-based rotation) */
  lastRefreshMessageCount: number;
}

/**
 * Sparse Post-Quantum Ratchet state (Section 5).
 *
 * Signal Protocol Section 5:
 * "The sparse post-quantum ratchet provides ~90% post-quantum protection
 * by periodically refreshing Kyber keys (not every message)."
 *
 * When combined with the EC Double Ratchet, this state supplies the profile's
 * post-quantum contribution to hybrid message-key derivation.
 *
 * State Structure:
 * - Root Key (RK): Derives new KDF chain keys when epoch changes
 * - Epoch: Current epoch number (increments with DH ratchet)
 * - KDF Chains: Per-epoch chains for deriving message keys
 * - MKSKIPPED: Skipped message keys for out-of-order delivery
 * - Direction: Communication direction (A2B or B2A)
 * - SCKA State: ML-KEM Braid state for continuous key agreement
 */
export interface SPQRState {
  /** Root Key for deriving new KDF chain keys */
  RK: Base64;

  /** Current epoch number (synchronized with DH ratchet) */
  epoch: number;

  /**
   * Latest epoch used for sending.
   *
   * Tracks send-epoch cleanup for SPQR forward secrecy while retaining receive
   * chains needed for in-flight messages.
   */
  sendEpoch?: number;

  /**
   * KDF chains per epoch.
   *
   * Map structure: epoch -> { send: KDFChain, receive: KDFChain }
   *
   * Each epoch has two chains:
   * - send: For encrypting outgoing messages
   * - receive: For decrypting incoming messages
   *
   * Note: Using Record instead of Map for JSON serialization compatibility.
   * Convert to/from Map in memory for better performance if needed.
   */
  kdfChains: Record<number, { send: KDFChain; receive: KDFChain }>;

  /**
   * Skipped message keys for out-of-order delivery.
   *
   * Map structure: epoch -> (index -> messageKey)
   *
   * Signal Protocol Section 4.6:
   * "Messages may arrive out of order. Store skipped message keys
   * to decrypt them later."
   *
   * Signal Protocol Section 8.4:
   * "A recommended policy is to delete message keys more than one week old"
   *
   * Note: Using Record for JSON serialization. The map holds keys as strings
   * in format "epoch:index" -> { key: Base64, timestamp: number }
   */
  MKSKIPPED: Record<
    string,
    {
      /** Message key */
      key: Base64;
      /** Timestamp of when this key entered the store (for expiration) */
      timestamp: number;
    }
  >;

  /** Communication direction */
  direction: 'A2B' | 'B2A';

  /** ML-KEM Braid state for continuous key agreement */
  sckaState: SCKAState;

  /**
   * SCKA mode used for this session.
   *
   * - `'braid'` (default): specification-defined ML-KEM Braid profile
   * - `'direct'`: Explicit direct ML-KEM-768 encapsulation mode
   *
   * Once set during session establishment, the mode stays fixed for the
   * lifetime of the session, which keeps the protocol consistent.
   *
   * @default 'braid'
   */
  mode: SCKAMode;

  /**
   * ML-KEM Braid agent state.
   *
   * Only present when mode is `braid`.
   */
  braidState?: MLKEMBraidAgentState;

  /**
   * Pending outgoing Braid chunks.
   *
   * Only present when mode is `braid` and the state machine holds queued chunks
   * for future message headers.
   */
  pendingOutgoingChunks?: MLKEMBraidMessage[];

  /**
   * Version negotiation state for this session.
   *
   * Tracks the negotiation process with the peer to agree on a protocol version.
   * Once negotiation completes, the version stays locked for the session lifetime.
   *
   * @see VersionNegotiationState
   */
  versionNegotiation?: VersionNegotiationState;

  /**
   * Resolved HKDF info strings for SPQR key derivation.
   */
  infoStrings?: ResolvedSPQRInfoStrings;

  /**
   * Resolved security limits for SPQR DoS and skipped-key handling.
   */
  limits?: ResolvedSPQRLimits;

  /**
   * Flag: next spqrSend() should do full KEM ratchet.
   *
   * Set to true by spqrRecv() after decapsulating kyber ciphertext,
   * and during bootstrap. Cleared by spqrSend() after performing the
   * encapsulation/keypair generation.
   *
   * `send()` decides whether to run a KEM exchange from this state. Callers
   * do not trigger the exchange separately.
   */
  needsSendRatchet?: boolean;
}

/**
 * Triple Ratchet state (Signal Protocol Section 6).
 *
 * Signal Protocol Section 6:
 *
 * > "The Triple Ratchet provides hybrid security by running two ratchets in parallel:
 * > 1. Elliptic Curve Double Ratchet (Section 3) - Classical security
 * > 2. Sparse Post-Quantum Ratchet (Section 5) - Post-quantum security
 * >
 * > Message keys are derived by combining both ratchets using KDF_HYBRID(),
 * > ensuring security if EITHER ratchet remains secure."
 *
 * Security boundary: hybrid confidentiality aims to survive failure of
 * one contribution only if the other contribution and the surrounding
 * authenticated protocol assumptions remain secure. Percentages and absolute
 * "quantum safe" guarantees are deliberately not assigned here.
 *
 * Implementation Strategy:
 * - EC state: Use existing SessionState fields (DHs, DHr, RK, CKs, CKr, etc.)
 * - SPQR state: New state structure (this interface)
 * - Message format: Composite headers (EC header + SCKA header)
 * - Key derivation: KDF_HYBRID(ec_mk, pq_mk) combines both message keys
 */
export interface TripleRatchetState {
  /**
   * SPQR state for post-quantum security.
   *
   * Note: the main SessionState fields hold EC Double Ratchet state
   * (DHs, DHr, RK, CKs, CKr, Ns, Nr, PN, receiverChains, etc.)
   *
   * This separation keeps the module boundary explicit:
   * - Main SessionState fields own EC Double Ratchet state
   * - tripleRatchet owns SPQR state and hybrid key material
   */
  spqrState: SPQRState;

  /**
   * Flag indicating if Triple Ratchet is active.
   *
   * Set to true once PQXDH produced the SPQR root material and the
   * manager initialized SPQR v1 state for the session.
   */
  enabled: boolean;

  /**
   * Timestamp of the moment Triple Ratchet became active.
   *
   * Used for metrics, debugging, and gradual rollout tracking.
   */
  enabledAt: number;
}

/**
 * Session manager configuration
 */
export interface SessionConfig {
  maxMessageKeys: number; // Max number of message keys to store for out-of-order messages
  sessionTimeout: number; // Milliseconds before a session counts as stale
}

/**
 * Session record wrapper for session archiving and versioning.
 *
 * Provides SessionRecord which supports the Sesame algorithm
 * for automatic session convergence. Maintains current session plus archived
 * sessions for handling race conditions and out-of-order establishment.
 *
 * From Signal Protocol:
 *
 * > "A device might have multiple sessions for the same remote device.
 * > The Sesame algorithm ensures convergence to a single active session."
 *
 * Session Lookup Architecture:
 * 1. A ProtocolAddress (userId:deviceId) LOOKS UP a session
 * 2. Within a SessionRecord, a baseKey IDENTIFIES a session state
 * 3. The baseKey is the initiator's ephemeral public key from X3DH/PQXDH
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface SessionRecord {
  /**
   * Current active session state.
   *
   * This is the session used for encrypting new messages.
   * May be null when no session remains outside the archive (rare edge case).
   */
  currentSession: SessionState | null;

  /**
   * Archived sessions indexed by baseKey for O(1) lookup.
   *
   * The initiator's ephemeral public key (`baseKey`) identifies a session
   * state.
   *
   * Used for:
   * - Handling race conditions during session establishment
   * - Decrypting messages from old sessions
   * - Implementing Sesame algorithm for session convergence
   *
   * Key: Base64-encoded baseKey (initiator's ephemeral public key)
   * Value: SessionState
   *
   * baseKey keys session records for fast lookup and spec-aligned
   * session recovery behavior.
   */
  archivedSessions: Record<Base64, SessionState>;

  /**
   * Protocol version for this persisted session record shape.
   *
   * The current format is version 4. The store rejects older versions and forces
   * session re-establishment instead of compatibility migration.
   */
  version: typeof CURRENT_SESSION_RECORD_VERSION;

  /**
   * Metadata about the session record.
   *
   * Useful for UI, logging, and session management.
   */
  metadata?: SessionRecordMetadata;
}

/**
 * Metadata for a session record.
 *
 * Combines UI/management metadata with SESAME session lifecycle tracking.
 * This lets the SESAME layer use SessionRecord directly, without a separate
 * SesameSessionRecord wrapper.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface SessionRecordMetadata {
  /** When the current session was last used */
  lastUsedAt?: number;

  /** Total number of messages sent in current session */
  messagesSent?: number;

  /** Total number of messages received in current session */
  messagesReceived?: number;

  /** Whether this session counts as active */
  isActive?: boolean;

  /** Human-readable label for debugging */
  label?: string;

  // ============================================================================
  // SESAME Session Lifecycle Fields
  // These fields support the SESAME algorithm for multi-device session management
  // ============================================================================

  /**
   * Timestamp of the moment this session began (milliseconds since epoch).
   * Used for session expiration calculations (MAXSEND, MAXRECV thresholds).
   *
   * @see SESAME spec Section 4.2 (Session expiration)
   */
  createdAt?: number;

  /**
   * Timestamp when this session was last used to send a message.
   * Null if never used to send. Used for MAXSEND expiration check.
   *
   * @see SESAME spec Section 4.2 (Session expiration)
   */
  lastSentAt?: number | null;

  /**
   * Timestamp when this session last successfully received/decrypted a message.
   * Null if never used to receive. Used for MAXRECV expiration check.
   *
   * @see SESAME spec Section 4.2 (Session expiration)
   */
  lastReceivedAt?: number | null;

  /**
   * Whether we created this session (initiating) or they did (responding).
   * Initiator sends PreKeyMessages until first response received.
   *
   * @see SESAME spec Section 2.2 (Session creation for senders/recipients)
   */
  isInitiator?: boolean;
}

function assertSessionStateIdentityProfile(value: unknown, label: string): asserts value is SessionState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a session-state object`);
  }

  const session = value as Partial<SessionState>;
  if (!session.identityKeyPair) {
    throw new Error(`${label} is missing its local identity key pair`);
  }
  if (!session.localIdentity || !session.remoteIdentity) {
    throw new Error(`${label} must bind both composite identities`);
  }
  if (
    (session.localIdentityType !== 'aci' && session.localIdentityType !== 'pni') ||
    (session.remoteIdentityType !== 'aci' && session.remoteIdentityType !== 'pni')
  ) {
    throw new Error(`${label} must bind both identity namespaces`);
  }

  // Encoding validates tuple version, tags, canonical Base64, and key lengths.
  encodeCompositeIdentityV1(session.localIdentity);
  encodeCompositeIdentityV1(session.remoteIdentity);
  const expectedLocalIdentity = createCompositeIdentityV1(session.identityKeyPair);
  if (!compositeIdentitiesEqual(expectedLocalIdentity, session.localIdentity)) {
    throw new Error(`${label} local identity does not match its identity key pair`);
  }
  if (typeof session.baseKey !== 'string' || session.baseKey.length === 0) {
    throw new Error(`${label} must contain a non-empty base key`);
  }
}

/**
 * Validate the current session-record profile without coercion.
 *
 * This validator is used before persistence and after decoding. It deliberately
 * rejects old records and pre-v4 objects that omit or mix identity tuples or
 * their ACI/PNI namespaces.
 */
export function assertCurrentSessionRecord(record: unknown): asserts record is SessionRecord {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('Session record must be an object');
  }

  const candidate = record as Partial<SessionRecord>;
  if (candidate.version !== CURRENT_SESSION_RECORD_VERSION) {
    throw new Error(
      `Unsupported session record version ${String(candidate.version)}; expected ${CURRENT_SESSION_RECORD_VERSION}`
    );
  }
  if (
    !candidate.archivedSessions ||
    typeof candidate.archivedSessions !== 'object' ||
    Array.isArray(candidate.archivedSessions)
  ) {
    throw new Error('Session record must contain an archived-session map');
  }
  if (candidate.currentSession !== null) {
    assertSessionStateIdentityProfile(candidate.currentSession, 'Current session');
  }

  for (const [baseKey, archived] of Object.entries(candidate.archivedSessions)) {
    assertSessionStateIdentityProfile(archived, `Archived session ${baseKey}`);
    if (archived.baseKey !== baseKey) {
      throw new Error(`Archived session ${baseKey} does not match its map key`);
    }
  }
}

/**
 * Helper functions for working with SessionRecords.
 *
 * `baseKey`, the initiator's ephemeral public key, identifies a session state.
 */
export namespace SessionRecord {
  /**
   * Maximum number of archived sessions to keep per address.
   *
   * The limit of 40 allows decryption from recent session states during
   * key rotation and multi-device scenarios.
   */
  export const MAX_ARCHIVED_SESSIONS = 40;

  /**
   * Create a new SessionRecord with a single session.
   *
   * @param session - Initial session state
   * @returns New SessionRecord
   */
  export function create(session: SessionState): SessionRecord {
    return {
      currentSession: session,
      archivedSessions: {},
      version: CURRENT_SESSION_RECORD_VERSION,
    };
  }

  /**
   * Archive the current session and optionally set a new one.
   *
   * The function moves the current session to archivedSessions, keyed by its
   * baseKey. It trims old archived sessions if we exceed maxArchived.
   *
   * @param record - SessionRecord to modify
   * @param newSession - Optional new session to set as current
   * @param maxArchived - Maximum number of archived sessions to keep (default: 5)
   * @returns Modified SessionRecord
   */
  export function archiveCurrent(
    record: SessionRecord,
    newSession: SessionState | null = null,
    maxArchived: number = MAX_ARCHIVED_SESSIONS
  ): SessionRecord {
    // Move current to archived using baseKey as key
    if (record.currentSession) {
      const baseKey = record.currentSession.baseKey;
      record.archivedSessions[baseKey] = record.currentSession;
    }

    // Trim old sessions if we exceed max (by lastUsedAt timestamp)
    const archivedKeys = Object.keys(record.archivedSessions);
    if (archivedKeys.length > maxArchived) {
      // Sort by lastUsedAt (oldest first) and remove oldest
      const sortedKeys = archivedKeys.sort((a, b) => {
        const sessionA = record.archivedSessions[asBase64(a)];
        const sessionB = record.archivedSessions[asBase64(b)];
        return (sessionA?.lastUsedAt ?? 0) - (sessionB?.lastUsedAt ?? 0);
      });

      // Remove oldest sessions
      const keysToRemove = sortedKeys.slice(0, archivedKeys.length - maxArchived);
      for (const key of keysToRemove) {
        delete record.archivedSessions[asBase64(key)];
      }
    }

    // Set new current
    record.currentSession = newSession;

    return record;
  }

  /**
   * Get all sessions (current + archived) in this record.
   *
   * @param record - SessionRecord
   * @returns Array of all sessions
   */
  export function getAllSessions(record: SessionRecord): SessionState[] {
    const sessions: SessionState[] = [];
    if (record.currentSession) {
      sessions.push(record.currentSession);
    }
    sessions.push(...Object.values(record.archivedSessions));
    return sessions;
  }

  /**
   * Find a session by baseKey.
   *
   * The initiator's ephemeral public key (`baseKey`) identifies a session
   * state.
   *
   * @param record - SessionRecord
   * @param baseKey - Base64-encoded baseKey to find
   * @returns SessionState if found, null otherwise
   */
  export function findSession(record: SessionRecord, baseKey: Base64): SessionState | null {
    // Check current session first
    if (record.currentSession?.baseKey === baseKey) {
      return record.currentSession;
    }
    // O(1) lookup in archived sessions
    return record.archivedSessions[baseKey] ?? null;
  }

  /**
   * Check if record has an active current session.
   *
   * @param record - SessionRecord
   * @returns true if current session exists
   */
  export function hasCurrentSession(record: SessionRecord): boolean {
    return record.currentSession !== null;
  }

  /**
   * Promote an archived session to current.
   *
   * Useful when receiving a message from an old session that should
   * become active again (Sesame algorithm).
   *
   * @param record - SessionRecord
   * @param baseKey - Base64-encoded baseKey of session to promote
   * @returns true if the function found and promoted the session
   */
  export function promoteSession(record: SessionRecord, baseKey: Base64): boolean {
    const sessionToPromote = record.archivedSessions[baseKey];
    if (!sessionToPromote) {
      return false;
    }

    // Archive current (if exists) using its baseKey
    if (record.currentSession) {
      const currentBaseKey = record.currentSession.baseKey;
      record.archivedSessions[currentBaseKey] = record.currentSession;
    }

    // Promote archived to current
    record.currentSession = sessionToPromote;
    delete record.archivedSessions[baseKey];

    return true;
  }

  /**
   * Get the number of archived sessions.
   *
   * @param record - SessionRecord
   * @returns Number of archived sessions
   */
  export function getArchivedCount(record: SessionRecord): number {
    return Object.keys(record.archivedSessions).length;
  }

  // ==========================================================================
  // SDK-oriented methods (API shape only)
  // ==========================================================================

  /**
   * Check if the session has a usable sender chain for encrypting messages.
   *
   * A session is usable for sending if:
   * 1. It has a current session
   * 2. The current session has sending chain keys (CKs)
   * 3. The session has not expired for sending (per SESAME MAXSEND threshold)
   *
   * @param record - SessionRecord to check
   * @param now - Current time (default: Date.now())
   * @returns true if the record can send with this session
   *
   */
  export function hasUsableSenderChain(record: SessionRecord, now: number = Date.now()): boolean {
    if (!record.currentSession) {
      return false;
    }

    const session = record.currentSession;

    // Check if session has sending chain key
    if (!session.CKs) {
      return false;
    }

    // Only unacknowledged sessions have an age-based send limit.
    if (session.hasReceivedMessage === false) {
      const sessionAge = now - session.createdAt;
      if (sessionAge > DEFAULT_SESAME_CONFIG.maxUnacknowledgedSessionAge) {
        return false;
      }
    }

    return true;
  }

  /**
   * Archive the current session state when receiving a new PreKeyMessage.
   *
   * - Move the current session to archived (if it exists)
   * - Clear the current session slot
   * - A separate step sets the new session from PreKeyMessage
   *
   * Called when:
   * - Receiving a PreKeyMessage from a device we already have a session with
   * - Identity key changes (possible MITM - archive for later decryption)
   * - Registration ID changes (device reinstall detected)
   *
   * @param record - SessionRecord to modify
   * @returns Modified SessionRecord with current session archived
   *
   */
  export function archiveCurrentState(record: SessionRecord): SessionRecord {
    return archiveCurrent(record, null);
  }

  /**
   * Serialize a SessionRecord to bytes for storage.
   *
   * Uses JSON serialization for simplicity and debuggability.
   * Future versions may use Protocol Buffers for efficiency.
   *
   * @param record - SessionRecord to serialize
   * @returns Serialized bytes
   *
   */
  export function serialize(record: SessionRecord): Uint8Array {
    const json = JSON.stringify(record);
    return new TextEncoder().encode(json);
  }

  /**
   * Deserialize a SessionRecord from bytes.
   *
   * @param buffer - Serialized bytes
   * @returns Deserialized SessionRecord
   * @throws Error if the buffer does not parse
   *
   */
  export function deserialize(buffer: Uint8Array): SessionRecord {
    const json = new TextDecoder().decode(buffer);
    const parsed = JSON.parse(json) as SessionRecord;

    // Validate required fields
    if (parsed.version === undefined) {
      throw new Error('Invalid SessionRecord: missing version');
    }
    if (parsed.archivedSessions === undefined) {
      throw new Error('Invalid SessionRecord: missing archivedSessions');
    }

    return parsed;
  }
}
