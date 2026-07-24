/**
 * Session State Factory
 *
 * Factory functions for creating Signal Protocol session states.
 * Encapsulates the common session creation logic for both initiator (Alice)
 * and responder (Bob) roles.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#initialization
 * @see https://signal.org/docs/specifications/x3dh/
 */

import { ProtocolAddress } from '../../types/address';
import * as CryptoUtils from '../crypto';
import { defaultSignalLogger, type ILogger } from '../../logger';
import type {
  CompositeIdentityV1,
  IdentityKeyPair,
  PublicKey,
  PrivateKey,
  EcSignedPreKey,
  IdentityType,
} from '../../keys';
import { createCompositeIdentityV1 } from '../../keys/identity';
import type { SessionState } from '../../types';
import { asBase64 } from '../../types/utils';

/**
 * HKDF additional byte ranges (64 bytes total, after 32-byte root key from X3DH)
 *
 * Signal Protocol HKDF output layout:
 * - bytes 0-31: Chain key (CK) for initial receiving chain
 * - bytes 32-63: Initial PQR key for SPQR auth_key
 */
export {};
export const HKDF_ADDITIONAL_RANGES = {
  /** Chain key for initial receiving chain */
  CK: { start: 0, end: 32 },
  /** Initial PQR key for SPQR auth_key */
  INITIAL_PQR_KEY: { start: 32, end: 64 },
} as const;

/**
 * Session factory input for initiator (Alice)
 *
 * Note: sessionId has been removed. Sessions are now identified by:
 * - Lookup: ProtocolAddress (remoteAddress)
 * - State ID: baseKey (ephemeralKeyPair.publicKey)
 */
export interface InitiatorSessionInput {
  /** Local user's protocol address */
  localAddress: ProtocolAddress;
  /** Remote user's protocol address (used for session lookup) */
  remoteAddress: ProtocolAddress;
  identityKeyPair: IdentityKeyPair;
  remoteIdentity: CompositeIdentityV1;
  remoteRegistrationId: number;
  recipientIdentityType: IdentityType;
  /** Ephemeral key pair generated during X3DH - publicKey becomes baseKey */
  ephemeralKeyPair: { publicKey: string; privateKey: string };
  remoteSignedPreKey: { keyId: number; publicKey: string };
  /** Root key (after KDF_RK ratchet step for initiator) */
  rootKey: Uint8Array;
  /** Sending chain key (from KDF_RK ratchet step) */
  sendingChainKey: Uint8Array;
  /** Receiving chain key (from HKDF additional bytes) */
  receivingChainKey: Uint8Array;
  usedOneTimePreKeyId?: number;
  usedKyberPreKeyId?: number;
  kyberCiphertext?: string;
  usedKemOneTimePreKeyId?: number;
  kemOneTimePreKeyCiphertext?: string;
  logger?: Required<ILogger>;
}

/**
 * Session factory input for responder (Bob)
 *
 * Note: sessionId has been removed. Sessions are now identified by:
 * - Lookup: ProtocolAddress (remoteAddress)
 * - State ID: baseKey (senderEphemeralKey from PreKeyMessage)
 *
 * LAZY INITIALIZATION (Signal Protocol Section 3.3):
 * Per RatchetInitBob, Bob's session is initialized with:
 * - DHr = None (not set until DHRatchet during first message decrypt)
 * - CKs = None (derived during DHRatchet)
 * - CKr = None (derived during DHRatchet)
 *
 * Chain keys are optional to support lazy initialization.
 */
export interface ResponderSessionInput {
  /** Local user's protocol address */
  localAddress: ProtocolAddress;
  /** Remote user's protocol address (Alice's address, used for session lookup) */
  remoteAddress: ProtocolAddress;
  /** Sender's ephemeral public key from PreKeyMessage - becomes baseKey */
  senderEphemeralKey: PublicKey;
  identityKeyPair: IdentityKeyPair;
  remoteIdentity: CompositeIdentityV1;
  remoteRegistrationId: number;
  localIdentityType: IdentityType;
  ecSignedPreKey: EcSignedPreKey;
  /** Root key (SK from X3DH/PQXDH - NOT ratcheted for lazy init) */
  rootKey: Uint8Array;
  /** Sending chain key - undefined for lazy init, derived during DHRatchet */
  sendingChainKey?: Uint8Array;
  /** Receiving chain key - undefined for lazy init, derived during DHRatchet */
  receivingChainKey?: Uint8Array;
  logger?: Required<ILogger>;
}

/**
 * Create session state for initiator (Alice)
 *
 * Implements Signal Protocol Section 3.3 RatchetInitAlice.
 * Alice's session state after performing X3DH key agreement.
 *
 * Key differences from responder:
 * - DHs = ephemeral key (generated during X3DH)
 * - DHr = partner's signed prekey
 * - RK = result of KDF_RK(SK, DH(DHs, DHr)) - already ratcheted
 * - CKs = sending chain key (from KDF_RK ratchet step)
 * - CKr = receiving chain key (from HKDF additional bytes)
 * - isInitiator = true
 * - baseKey = ephemeralKeyPair.publicKey (session state identifier)
 *
 * @param input Session creation input
 * @returns Initialized session state
 */
export function createInitiatorSession(input: InitiatorSessionInput): SessionState {
  const {
    localAddress,
    remoteAddress,
    identityKeyPair,
    remoteIdentity,
    remoteRegistrationId,
    recipientIdentityType,
    ephemeralKeyPair,
    remoteSignedPreKey,
    rootKey,
    sendingChainKey,
    receivingChainKey,
    usedOneTimePreKeyId,
    usedKyberPreKeyId,
    kyberCiphertext,
    usedKemOneTimePreKeyId,
    kemOneTimePreKeyCiphertext,
    logger = defaultSignalLogger,
  } = input;

  // DIAGNOSTIC: Log session creation with key fingerprints
  logger.breadcrumb('createInitiatorSession: Creating session with keys', {
    category: 'E2EE',
    level: 'debug',
    data: {
      operation: 'factory-initiator-session',
      DHsPublicKey: ephemeralKeyPair.publicKey.substring(0, 20),
      DHr: remoteSignedPreKey.publicKey.substring(0, 20),
      isInitiator: true,
      localAddress: `${localAddress.userId}:${localAddress.deviceId}`,
      remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
    },
  });

  return {
    // baseKey = initiator's ephemeral public key
    baseKey: asBase64(ephemeralKeyPair.publicKey),
    localAddress,
    remoteAddress,
    localDeviceId: localAddress.deviceId,
    remoteDeviceId: remoteAddress.deviceId,
    localRegistrationId: identityKeyPair.registrationId,
    remoteRegistrationId,

    // Independent-profile identity commitments are derived from these tuples.
    identityKeyPair,
    localIdentity: createCompositeIdentityV1(identityKeyPair),
    remoteIdentity,
    localIdentityType: 'aci',
    remoteIdentityType: recipientIdentityType,

    // Root key (already ratcheted via KDF_RK(SK, DH(DHs, DHr)))
    RK: asBase64(CryptoUtils.bytesToBase64(rootKey)),

    // DH ratchet keys
    // Alice: DHs = her ephemeral key, DHr = partner's signed prekey
    DHs: {
      publicKey: ephemeralKeyPair.publicKey as PublicKey,
      privateKey: ephemeralKeyPair.privateKey as PrivateKey,
    },
    DHr: remoteSignedPreKey.publicKey as PublicKey,

    // Chain keys (pre-computed by caller)
    CKs: asBase64(CryptoUtils.bytesToBase64(sendingChainKey)),
    CKr: asBase64(CryptoUtils.bytesToBase64(receivingChainKey)),

    // Message counters
    Ns: 0,
    Nr: 0,
    PN: 0,

    // Skipped message keys
    receiverChains: [],

    // X3DH prekey tracking
    recipientIdentityType,
    usedSignedPreKeyId: remoteSignedPreKey.keyId,
    usedOneTimePreKeyId,
    usedKyberPreKeyId,
    usedKemOneTimePreKeyId,

    // PQXDH temporary data
    kyberCiphertext: kyberCiphertext ? asBase64(kyberCiphertext) : undefined,
    kemOneTimePreKeyCiphertext: kemOneTimePreKeyCiphertext
      ? asBase64(kemOneTimePreKeyCiphertext)
      : undefined,

    // Session role
    isInitiator: true,

    // PreKeyMessage flag: Send PreKeyMessages until responder acknowledges
    // If the first message is lost, subsequent messages must also be PreKeyMessages
    unacknowledgedPreKeyMessage: true,

    // Unacknowledged session tracking
    // Initiator hasn't received any message yet
    hasReceivedMessage: false,

    // Metadata
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

/**
 * Create session state for responder (Bob)
 *
 * Implements Signal Protocol Section 3.3 RatchetInitBob with LAZY initialization.
 * Bob's session state after receiving Alice's PreKeyMessage.
 *
 * LAZY INITIALIZATION (per Signal Protocol Section 3.3):
 * - DHs = signed prekey (which Alice knows)
 * - DHr = undefined (NOT set until DHRatchet during first message decrypt)
 * - RK = SK (NOT ratcheted, unlike initiator)
 * - CKs = undefined (NOT set until DHRatchet)
 * - CKr = undefined (NOT set until DHRatchet)
 * - isInitiator = false
 * - baseKey = senderEphemeralKey (Alice's ephemeral public key from PreKeyMessage)
 *
 * When Bob receives Alice's first message and calls decrypt():
 * 1. DHRatchet detects DHr is undefined (or mismatches header.dh)
 * 2. DHRatchet step runs, deriving CKr from DH(DHs, header.dh)
 * 3. DHRatchet generates new DHs keypair and derives CKs
 *
 * @param input Session creation input
 * @returns Initialized session state
 */
export function createResponderSession(input: ResponderSessionInput): SessionState {
  const {
    localAddress,
    remoteAddress,
    senderEphemeralKey,
    identityKeyPair,
    remoteIdentity,
    remoteRegistrationId,
    localIdentityType,
    ecSignedPreKey,
    rootKey,
    sendingChainKey,
    receivingChainKey,
    logger = defaultSignalLogger,
  } = input;

  // DIAGNOSTIC: Log session creation with key fingerprints
  logger.breadcrumb('createResponderSession: Creating session with keys', {
    category: 'E2EE',
    level: 'debug',
    data: {
      operation: 'factory-responder-session',
      DHsPublicKey: ecSignedPreKey.publicKey.substring(0, 20),
      DHr: 'undefined (lazy init)',
      senderEphemeralKey: (typeof senderEphemeralKey === 'string'
        ? senderEphemeralKey
        : '(Uint8Array)'
      ).substring(0, 20),
      isInitiator: false,
      localAddress: `${localAddress.userId}:${localAddress.deviceId}`,
      remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
    },
  });

  return {
    // baseKey = initiator's ephemeral public key
    // For responder, this comes from PreKeyMessage.senderEphemeralKey
    baseKey: asBase64(senderEphemeralKey),
    localAddress,
    remoteAddress,
    localDeviceId: localAddress.deviceId,
    remoteDeviceId: remoteAddress.deviceId,
    localRegistrationId: identityKeyPair.registrationId,
    remoteRegistrationId,

    // Independent-profile identity commitments are derived from these tuples.
    identityKeyPair,
    localIdentity: createCompositeIdentityV1(identityKeyPair),
    remoteIdentity,
    localIdentityType,
    remoteIdentityType: 'aci',

    // Root key (NOT ratcheted - RK = SK from X3DH/PQXDH)
    RK: asBase64(CryptoUtils.bytesToBase64(rootKey)),

    // DH ratchet keys
    // Bob: DHs = signed prekey (for first DHRatchet DH operation)
    // DHr = undefined per RatchetInitBob - set during DHRatchet in decrypt()
    DHs: {
      publicKey: ecSignedPreKey.publicKey,
      privateKey: ecSignedPreKey.privateKey,
    },
    DHr: undefined, // LAZY: Set during DHRatchet when receiving first message

    // Chain keys - LAZY: undefined until DHRatchet derives them
    CKs: sendingChainKey ? asBase64(CryptoUtils.bytesToBase64(sendingChainKey)) : undefined,
    CKr: receivingChainKey ? asBase64(CryptoUtils.bytesToBase64(receivingChainKey)) : undefined,

    // Message counters
    Ns: 0,
    Nr: 0,
    PN: 0,

    // Skipped message keys
    receiverChains: [],

    // Session role
    isInitiator: false,

    // Unacknowledged session tracking
    // Responder has received the PreKeyMessage
    hasReceivedMessage: true,

    // Metadata
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

// ============================================================================
// Signal Protocol Spec Aliases (SCREAMING_SNAKE_CASE per spec naming)
// Per Signal Protocol Double Ratchet Section 3.3 RatchetInitAlice / RatchetInitBob
// ============================================================================

/**
 * Alias for createInitiatorSession.
 * Per Signal Protocol Section 3.3 - "RatchetInitAlice(state, SK, bob_dh_public_key)"
 */
export const RATCHET_INIT_ALICE = createInitiatorSession;

/**
 * Alias for createResponderSession.
 * Per Signal Protocol Section 3.3 - "RatchetInitBob(state, SK, bob_dh_key_pair)"
 */
export const RATCHET_INIT_BOB = createResponderSession;
