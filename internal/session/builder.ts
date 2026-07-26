/**
 * Session Establishment - Orchestrates X3DH/PQXDH + Session Creation
 *
 * Handles the session establishment phase of the Signal Protocol.
 * Creates session states for both initiator (Alice) and responder (Bob).
 *
 * This module orchestrates:
 * - Key agreement via handshake.ts (X3DH/PQXDH)
 * - Initial DH ratchet step for initiator
 * - Session state creation via factory.ts
 *
 * Note: Triple Ratchet (SPQR) initialization remains in the orchestrator
 * since it's a higher-level concern that depends on session state.
 *
 * @see https://signal.org/docs/specifications/x3dh/
 * @see https://signal.org/docs/specifications/pqxdh/
 * @see https://signal.org/docs/specifications/doubleratchet/#initialization
 */

import { defaultSignalProtocolLogger } from '../../logger';
import * as CryptoUtils from '../crypto';
import type { PublicKey } from '../../keys';
import { performKeyAgreement, performResponderKeyAgreement } from './handshake';
import { createInitiatorSession, createResponderSession, HKDF_ADDITIONAL_RANGES } from './factory';
import type {
  SessionBuilderInitiatorInput,
  SessionBuilderInitiatorResult,
  SessionBuilderResponderInput,
  SessionBuilderResponderResult,
} from './types';
import { asBase64 } from '../../types/utils';

/**
 * SessionBuilder - Handles session establishment via X3DH/PQXDH
 *
 * This class provides static methods for creating initiator and responder
 * session state.
 *
 * Session Identification:
 * - Sessions are LOOKED UP by ProtocolAddress (userId:deviceId)
 * - Session STATES are IDENTIFIED by baseKey (initiator's ephemeral public key)
 * - sessionId has been removed - use remoteAddress for lookup, baseKey for state ID
 *
 * @example
 * ```typescript
 * // As initiator (Alice)
 * const result = await SessionBuilder.buildInitiatorSession({
 *   localAddress: ProtocolAddress.create(aliceId, 1),
 *   remoteAddress: ProtocolAddress.create(bobId, 1),
 *   identityKeyPair: aliceIdentity,
 *   preKeyBundle: bobPreKeyBundle,
 * });
 *
 * // As responder (Bob)
 * const result = await SessionBuilder.buildResponderSession({
 *   localAddress: ProtocolAddress.create(bobId, 1),
 *   remoteAddress: ProtocolAddress.create(aliceId, 1),
 *   identityKeyPair: bobIdentity,
 *   prekeyMessage: alicePreKeyMessage,
 *   ecSignedPreKey: bobSignedPreKey,
 *   ecOneTimePreKey: bobOneTimePreKey,
 *   kemLastResortPreKey: bobKyberPreKey,
 * });
 * ```
 */
export {};
export class SessionBuilder {
  /**
   * Build a session as initiator (Alice)
   *
   * Implements Signal Protocol Section 3.3 RatchetInitAlice (with PQXDH extension).
   * Performs X3DH/PQXDH key agreement and creates the initial session state.
   *
   * Steps:
   * 1. Perform X3DH/PQXDH key agreement (delegates to handshake module)
   * 2. Perform initial DH ratchet step (per RatchetInitAlice)
   * 3. Create session state using factory
   * 4. Preserve original SK for Triple Ratchet initialization
   *
   * @param input Session builder input
   * @returns Session state and metadata
   *
   * @see https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol
   * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol
   * @see https://signal.org/docs/specifications/doubleratchet/#initialization
   */
  static async buildInitiatorSession(
    input: SessionBuilderInitiatorInput
  ): Promise<SessionBuilderInitiatorResult> {
    const {
      localAddress,
      remoteAddress,
      identityKeyPair,
      prekeyBundle,
      recipientIdentityType,
      protocolStrategy,
      logger = defaultSignalProtocolLogger,
    } = input;

    logger.breadcrumb('SessionBuilder: Building initiator session', {
      category: 'E2EE',
      level: 'info',
      data: {
        remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
        operation: 'build-initiator',
      },
    });

    // ========================================================================
    // Step 1: Perform Key Agreement (X3DH or PQXDH)
    // ========================================================================

    const keyAgreementResult = await performKeyAgreement(identityKeyPair, prekeyBundle, {
      protocolStrategy,
      remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
      logger,
    });

    const {
      sharedSecret: initialRootKey,
      additionalDerivedBytes,
      ephemeralKeyPair: ephemeralKey,
      kyberCiphertext,
      usedKyberPreKeyId: kyberPreKeyId,
      kemOneTimePreKeyCiphertext,
      usedKemOneTimePreKeyId,
      usedPQXDH,
      usedClassicalFallback,
    } = keyAgreementResult;

    // ========================================================================
    // Step 2: Preserve Original SK for Triple Ratchet
    // ========================================================================

    // Preserve INITIAL_PQR_KEY for Triple Ratchet initialization. The SPQR
    // authenticator key is bytes 64-95 of the PQXDH output, not the root key.
    const initialRootKeyForSPQR =
      usedPQXDH && additionalDerivedBytes
        ? new Uint8Array(
            additionalDerivedBytes.slice(
              HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.start,
              HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.end
            )
          )
        : undefined;

    // ========================================================================
    // Step 3: Perform Initial DH Ratchet (RatchetInitAlice)
    // ========================================================================

    // Per Signal Protocol Section 3.3 - RatchetInitAlice:
    // Alice MUST perform a DH ratchet step during initialization using KDF_RK
    // This derives: state.RK, state.CKs
    logger.debug('Alice performing initial DH ratchet (Section 3.3)', {
      category: 'E2EE',
      data: { operation: 'init-alice', step: 'dh-ratchet' },
    });

    // Use the same ephemeral key from X3DH as our initial DH ratchet key (DHs)
    // This ephemeral key will be sent in the PreKeyMessage so the responder can derive
    // the same shared secret.
    const dhOutput = await CryptoUtils.computeSharedSecret(
      asBase64(ephemeralKey.privateKey), // DHs (Alice's ephemeral key from X3DH)
      prekeyBundle.ecSignedPreKey.publicKey // DHr (Bob's signed prekey)
    );

    // Perform KDF_RK to derive new root key and sending chain key
    const { rootKey: ratchetedRootKey, chainKey: sendingChainKey } = await CryptoUtils.kdfRootKey(
      initialRootKey, // SK from X3DH
      dhOutput
    );

    // Best-effort overwrite owned DH/root typed arrays after use.
    CryptoUtils.secureZeroBytes(dhOutput);
    CryptoUtils.secureZeroBytes(initialRootKey);

    logger.debug('Alice DH ratchet complete', {
      category: 'E2EE',
      data: {
        operation: 'init-alice',
        rootKeyLength: ratchetedRootKey.length,
      },
    });

    // ========================================================================
    // Step 4: Derive Receiving Chain Key
    // ========================================================================

    // Alice's receiving chain key (CKr):
    // Per spec, Bob hasn't sent anything yet, so CKr could be undefined.
    // However, for compatibility, we derive it from X3DH HKDF.
    const receivingChainKey =
      additionalDerivedBytes?.slice(
        HKDF_ADDITIONAL_RANGES.CK.start,
        HKDF_ADDITIONAL_RANGES.CK.end
      ) ?? new Uint8Array(32);

    // ========================================================================
    // Step 5: Create Session State
    // ========================================================================

    const sessionState = createInitiatorSession({
      localAddress,
      remoteAddress,
      identityKeyPair,
      remoteIdentity: prekeyBundle.identity,
      remoteRegistrationId: prekeyBundle.registrationId,
      recipientIdentityType,
      ephemeralKeyPair: ephemeralKey,
      remoteSignedPreKey: prekeyBundle.ecSignedPreKey,
      rootKey: ratchetedRootKey,
      sendingChainKey,
      receivingChainKey,
      usedOneTimePreKeyId: prekeyBundle.ecOneTimePreKey?.keyId,
      usedKyberPreKeyId: kyberPreKeyId,
      kyberCiphertext,
      usedKemOneTimePreKeyId,
      kemOneTimePreKeyCiphertext,
      logger,
    });

    logger.breadcrumb('SessionBuilder: Initiator session built', {
      category: 'E2EE',
      level: 'info',
      data: {
        baseKey: sessionState.baseKey.substring(0, 20),
        usedPQXDH,
        usedClassicalFallback: !!usedClassicalFallback,
      },
    });

    return {
      sessionState,
      kyberCiphertext,
      kyberPreKeyId,
      initialRootKeyForSPQR,
      usedPQXDH,
      usedClassicalFallback,
    };
  }

  /**
   * Build a session as responder (Bob)
   *
   * Implements Signal Protocol Section 3.3 RatchetInitBob (with PQXDH extension).
   * Called when Bob receives Alice's first PreKeyMessage.
   *
   * Key difference from initiator:
   * - Bob does NOT perform a DH ratchet during initialization
   * - Bob's RK = SK (not ratcheted like Alice's)
   * - Bob will ratchet when receiving Alice's first message
   *
   * @param input Session builder input
   * @returns Session state and metadata
   *
   * @see https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol
   * @see https://signal.org/docs/specifications/doubleratchet/#initialization
   */
  static async buildResponderSession(
    input: SessionBuilderResponderInput
  ): Promise<SessionBuilderResponderResult> {
    const {
      localAddress,
      remoteAddress,
      identityKeyPair,
      prekeyMessage,
      ecSignedPreKey,
      ecOneTimePreKey,
      kemLastResortPreKey,
      kemOneTimePreKey,
      protocolStrategy,
      logger = defaultSignalProtocolLogger,
    } = input;

    logger.breadcrumb('SessionBuilder: Building responder session', {
      category: 'E2EE',
      level: 'info',
      data: {
        remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
        operation: 'build-responder',
      },
    });

    // ========================================================================
    // Step 1: Validate PreKeyMessage
    // ========================================================================

    if (prekeyMessage.usedSignedPreKeyId === undefined) {
      throw new Error('PreKeyMessage missing usedSignedPreKeyId');
    }

    const aliceIdentityKey = prekeyMessage.senderIdentity.x25519PublicKey;
    const aliceEphemeralKey = prekeyMessage.senderEphemeralKey;

    // ========================================================================
    // Step 2: Perform Key Agreement
    // ========================================================================

    const keyAgreementResult = await performResponderKeyAgreement(
      identityKeyPair,
      ecSignedPreKey,
      ecOneTimePreKey,
      kemLastResortPreKey,
      kemOneTimePreKey,
      prekeyMessage,
      aliceIdentityKey,
      aliceEphemeralKey,
      {
        protocolStrategy,
        remoteAddress: `${remoteAddress.userId}:${remoteAddress.deviceId}`,
        logger,
      }
    );

    const {
      sharedSecret: rootKey,
      additionalDerivedBytes,
      usedPQXDH,
      usedClassicalFallback,
    } = keyAgreementResult;

    // ========================================================================
    // Step 3: LAZY Session Initialization (per Signal Protocol Section 3.3)
    // ========================================================================

    // Per Signal Protocol Section 3.3 - RatchetInitBob:
    // Bob's session initialization is LAZY - he does NOT perform the DH ratchet
    // during session establishment.
    //
    // RatchetInitBob sets:
    //   state.DHs = bob_dh_key_pair    (Bob's signed prekey)
    //   state.DHr = None               (NOT set until first message decrypt)
    //   state.RK = SK                  (NOT ratcheted - direct from X3DH/PQXDH)
    //   state.CKs = None               (NOT set until DHRatchet)
    //   state.CKr = None               (NOT set until DHRatchet)
    //
    // The DHRatchet step happens DURING decrypt when Bob receives Alice's first
    // message. At that point:
    //   1. state.DHr = header.dh (Alice's ephemeral)
    //   2. state.RK, state.CKr = KDF_RK(...)
    //   3. state.DHs = GENERATE_DH() (NEW keypair!)
    //   4. state.RK, state.CKs = KDF_RK(...)
    logger.debug('Bob using LAZY session initialization (Section 3.3)', {
      category: 'E2EE',
      data: { operation: 'init-bob', approach: 'lazy' },
    });

    // ========================================================================
    // Step 4: Create Session State (LAZY - no chain keys yet)
    // ========================================================================

    const sessionState = createResponderSession({
      localAddress,
      remoteAddress,
      senderEphemeralKey: aliceEphemeralKey as PublicKey,
      identityKeyPair,
      remoteIdentity: prekeyMessage.senderIdentity,
      remoteRegistrationId: prekeyMessage.senderRegistrationId,
      localIdentityType: prekeyMessage.recipientIdentityType,
      ecSignedPreKey,
      rootKey, // SK directly - NOT ratcheted
      // Chain keys are undefined - will be derived during DHRatchet in cipher.decrypt()
      logger,
    });

    logger.breadcrumb('SessionBuilder: Responder session built (lazy init)', {
      category: 'E2EE',
      level: 'info',
      data: {
        baseKey: sessionState.baseKey.substring(0, 20),
        usedPQXDH,
        usedClassicalFallback: !!usedClassicalFallback,
        lazyInit: true,
        DHrSet: sessionState.DHr !== undefined,
        CKsSet: sessionState.CKs !== undefined,
        CKrSet: sessionState.CKr !== undefined,
      },
    });

    // When PQXDH is active, preserve bytes 64-95 as the SPQR authenticator key.
    const initialRootKeyForSPQR =
      usedPQXDH && additionalDerivedBytes
        ? new Uint8Array(
            additionalDerivedBytes.slice(
              HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.start,
              HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.end
            )
          )
        : undefined;

    logger.debug('BuilderResponderSession: Returning result', {
      category: 'E2EE',
      data: {
        operation: 'builder-responder',
        usedPQXDH,
        usedClassicalFallback: !!usedClassicalFallback,
        hasInitialRootKeyForSPQR: !!initialRootKeyForSPQR,
        initialRootKeyLength: initialRootKeyForSPQR?.length,
      },
    });

    return {
      sessionState,
      usedPQXDH,
      initialRootKeyForSPQR,
      usedClassicalFallback,
    };
  }
}
