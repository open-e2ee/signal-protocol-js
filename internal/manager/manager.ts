/**
 * Signal Protocol Manager
 *
 * Core implementation of the Signal Protocol for end-to-end encrypted messaging.
 * This module orchestrates the complete encryption lifecycle including key generation,
 * session establishment, message encryption/decryption, and key rotation.
 *
 * @module protocol/manager
 *
 * ## Architecture Overview
 *
 * The manager coordinates three main cryptographic components:
 *
 * 1. **X3DH/PQXDH Key Agreement** - Establishes shared secrets for new sessions
 *    - X3DH: Extended Triple Diffie-Hellman (classical security)
 *    - PQXDH: Post-Quantum X3DH with ML-KEM-1024 (quantum-resistant)
 *
 * 2. **Double Ratchet Algorithm** - Provides forward secrecy per message
 *    - Symmetric-key ratchet for message key derivation
 *    - Diffie-Hellman ratchet for recovering from key compromise
 *
 * 3. **Key Management** - Handles identity, prekeys, and rotation
 *    - Identity keys: Long-lived, per-user Ed25519 signing + X25519 DH
 *    - Signed prekeys: Weekly rotation, signed by identity key
 *    - One-time prekeys: Single-use, consumed atomically
 *    - Kyber prekeys: Post-quantum ML-KEM-1024 keys
 *
 * ## Thread Safety
 *
 * Uses per-session AsyncLock to prevent race conditions during concurrent
 * encrypt/decrypt operations. Different sessions don't block each other.
 *
 * ## Specification References
 *
 * @see https://signal.org/docs/specifications/x3dh/ - X3DH key agreement
 * @see https://signal.org/docs/specifications/doubleratchet/ - Double Ratchet
 * @see https://signal.org/docs/specifications/pqxdh/ - Post-Quantum X3DH
 *
 * @example Basic usage with SignalProtocolClient (recommended)
 * ```typescript
 * import { SignalProtocolClient } from '../../index';
 *
 * const client = await SignalProtocolClient.create('user-123', { storage });
 * const encrypted = await client.encryptMessage(sessionId, 'Hello!');
 * ```
 *
 * @example Direct protocol manager usage (advanced)
 * ```typescript
 * import { SignalProtocolManager } from './';
 *
 * const manager = new SignalProtocolManager(storage);
 * await manager.initialize();
 * await manager.generatePreKeyBundle(userId);
 * await manager.startSession(sessionId, remoteAddress, bundle, localUserId);
 * const ciphertext = await manager.encrypt(sessionId, 'Hello!');
 * ```
 */

import AsyncLock from 'async-lock';
import { defaultSignalProtocolLogger, type ILogger } from '../../logger';
import type {
  Ciphertext,
  IdentityKeyPair,
  KemOneTimePreKey,
  KyberPreKey,
  EcOneTimePreKey,
  PreKeyBundle,
  PublicKey,
  EcSignedPreKey,
} from '../../keys';
import type {
  ISignalProtocolLocalStore,
  ISignalProtocolManager,
  PreKeyMessage,
  SessionState,
  SessionRecord,
} from '../../types';
import { CURRENT_SESSION_RECORD_VERSION } from '../../types/session';
import {
  EncryptionError,
  EncryptionErrorCode,
  TrustDirection,
  UntrustedIdentityError,
} from '../../types';
import { DEFAULT_RATCHET_CONFIG } from '../protocol/double-ratchet';
import { ProtocolAddress } from '../../types/address';
import type { ProtocolStrategyConfig } from '../../types';
import { resolveSCKAMode } from '../../types/protocol-config';
// DEFAULT_DEVICE_ID removed - device IDs must be explicitly provided
import * as CryptoUtils from '../crypto';
import * as SPQR from '../protocol/spqr';
import type {
  DoubleRatchetConfig,
  DoubleRatchetState,
  RatchetKeyPair,
} from '../protocol/double-ratchet';
import { cleanupExpiredKeys as moduleCleanupExpiredKeys } from '../protocol/double-ratchet';
import type { IdentityType } from '../../keys/types';
import {
  generateIdentityKeyPair,
  generateEcSignedPreKey,
  generateEcOneTimePreKeys,
  generateKyberLastResortPreKey,
} from '../../keys';
import { SessionBuilder, SessionCipher } from '../session';

/**
 * Signal Protocol Manager implementation
 *
 * Provides the core Signal Protocol functionality including:
 * - Identity key generation and management
 * - Prekey bundle generation (signed + one-time + Kyber)
 * - X3DH/PQXDH key agreement for session establishment
 * - Double Ratchet encryption/decryption with forward secrecy
 * - Key rotation (weekly for signed prekeys)
 * - Message key cleanup (per spec section 8.4)
 *
 * This class implements {@link ISignalProtocolManager} and is typically used
 * internally by {@link SignalProtocolClient}. Direct usage is for advanced scenarios.
 *
 * @implements {ISignalProtocolManager}
 *
 * @example Dependency injection for custom composition
 * ```typescript
 * const store = new InMemorySignalProtocolStore();
 * const manager = new SignalProtocolManager(store);
 * await manager.initialize();
 * ```
 *
 * @see SignalProtocolClient - High-level API for most use cases
 * @see ISignalProtocolManager - Interface definition
 */
export {};
export class SignalProtocolManager implements ISignalProtocolManager {
  private keyStorage: ISignalProtocolLocalStore;
  private initialized = false;
  private readonly logger: Required<ILogger>;

  /** Protocol strategy configuration for PQXDH and SPQR. */
  private readonly protocolStrategy?: ProtocolStrategyConfig;

  /**
   * Local user's ID, set during generatePreKeyBundle or initialization.
   * Used to create ProtocolAddress for session establishment as responder.
   */
  private localUserId: string | null = null;

  /**
   * Local device ID, set during generatePreKeyBundle.
   * Used to create ProtocolAddress for session establishment as responder.
   */
  private localDeviceId: number | null = null;

  /**
   * Async lock for concurrent safety
   *
   * Prevents race conditions when multiple encrypt/decrypt operations
   * happen concurrently on the same session. Uses per-session locks
   * so different conversations don't block each other.
   */
  private lock = new AsyncLock({
    timeout: 5000, // 5 second timeout prevents deadlocks
    maxPending: 1000, // Max 1000 queued operations per session
  });

  /**
   * SessionCipher handles encrypt/decrypt operations.
   * Lazily initialized on first use.
   */
  private sessionCipher: SessionCipher | null = null;

  /**
   * Create a new SignalProtocolManager instance
   *
   * @param storage - Local protocol storage implementation.
   * @param protocolStrategy - Optional protocol strategy for PQXDH/SPQR behavior.
   */
  constructor(
    storage: ISignalProtocolLocalStore,
    protocolStrategy?: ProtocolStrategyConfig,
    logger: Required<ILogger> = defaultSignalProtocolLogger
  ) {
    this.logger = logger;
    this.keyStorage = storage;
    this.protocolStrategy = protocolStrategy;
  }

  /**
   * Get or create the SessionCipher instance.
   * SessionCipher is lazily initialized to allow manager setup first.
   */
  private getSessionCipher(): SessionCipher {
    if (!this.sessionCipher) {
      this.sessionCipher = new SessionCipher(
        this.keyStorage,
        this.establishSessionFromPreKeyMessage.bind(this),
        this.lock,
        { protocolStrategy: this.protocolStrategy },
        this.logger
      );
    }
    return this.sessionCipher;
  }

  /**
   * Callback for SessionCipher to establish a session from a PreKeyMessage.
   * This method is called when decrypt() receives a PreKeyMessage and no session exists.
   *
   * Note: Updated to use ProtocolAddress per session identification architecture changes.
   */
  private async establishSessionFromPreKeyMessage(
    remoteAddress: ProtocolAddress,
    prekeyMessage: PreKeyMessage
  ): Promise<SessionState> {
    return this.performX3DHResponder(remoteAddress, prekeyMessage);
  }

  /**
   * Get lock key for a specific session
   * Each session has its own lock to prevent cross-conversation blocking
   */
  private getLockKey(sessionId: string): string {
    return `session:${sessionId}`;
  }

  // ============================================================================
  // Double Ratchet State Adapters (SessionState ↔ DoubleRatchetState)
  // ============================================================================

  /**
   * Extract Double Ratchet state from SessionState for delegation to module.
   *
   * This allows manager.ts to delegate ratchet operations to the double-ratchet
   * module while keeping the full SessionState structure for other purposes.
   *
   * @throws Error if session is not initialized (DHs or DHr is null)
   */
  private extractRatchetState(session: SessionState): DoubleRatchetState {
    // Validate session has been fully initialized with DH keys and chain keys
    // For lazy initialization (responder), this should only be called AFTER
    // the first DHRatchet step has completed and set all keys.
    if (!session.DHs) {
      throw new Error('Cannot extract ratchet state: DHs is null (session not initialized)');
    }
    if (!session.DHr) {
      throw new Error('Cannot extract ratchet state: DHr is undefined (lazy init not complete)');
    }
    if (!session.CKs || !session.CKr) {
      throw new Error(
        'Cannot extract ratchet state: Chain keys undefined (lazy init not complete)'
      );
    }

    return {
      DHs: session.DHs as RatchetKeyPair,
      DHr: session.DHr,
      RK: session.RK,
      CKs: session.CKs,
      CKr: session.CKr,
      Ns: session.Ns,
      Nr: session.Nr,
      PN: session.PN,
      receiverChains: session.receiverChains ?? [],
      processedChains: session.processedChains,
    };
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  /**
   * Initialize identity keys on first launch
   *
   * This method should:
   * 1. Check if identity key already exists
   * 2. If not, generate a new identity key pair
   * 3. Store private key in SecureStore
   * 4. Upload public key to Convex
   *
   */
  async initialize(identityTypes: readonly IdentityType[] = ['aci', 'pni']): Promise<void> {
    try {
      // Generate identity keys for active identity types (Signal Protocol dual-identity architecture)
      for (const type of identityTypes) {
        await this.initializeIdentity(type);
      }

      this.initialized = true;
      this.logger.breadcrumb(
        `Signal Protocol initialized successfully (${identityTypes.join(' + ').toUpperCase()})`,
        {
          category: 'E2EE',
          level: 'info',
        }
      );
    } catch (error) {
      throw new EncryptionError(
        'Failed to initialize Signal Protocol',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Initialize identity key for a specific identity type (ACI or PNI).
   *
   * Generates and stores an identity key pair if one does not already exist
   * for the given identity type.
   *
   * @param identityType - 'aci' (account) or 'pni' (phone number)
   */
  private async initializeIdentity(identityType: IdentityType): Promise<void> {
    const hasKey = await this.keyStorage.hasIdentityKey(identityType);
    if (hasKey) {
      return;
    }

    // Generate identity key using Signal Protocol (P-256 ECDH + ECDSA)
    const identityKeyPair = await this.generateIdentityKey();

    // Store identity key for this identity type
    await this.keyStorage.storeIdentityKey(identityKeyPair, identityType);

    this.logger.breadcrumb(`Identity key generated for ${identityType}`, {
      category: 'E2EE',
      level: 'info',
      data: { identityType },
    });
  }

  /**
   * Set local user and device identity.
   *
   * This must be called before any session operations (encrypt/decrypt).
   * It's normally called by generatePreKeyBundle, but can be called directly
   * when keys already exist and don't need regeneration.
   *
   * @param userId - User ID for this client
   * @param deviceId - Device ID (1 for primary, 2-5 for linked devices)
   */
  setLocalIdentity(userId: string, deviceId: number): void {
    this.localUserId = userId;
    this.localDeviceId = deviceId;
  }

  /**
   * Generate and upload prekey bundle
   *
   * This method should:
   * 1. Generate signed prekey (rotates weekly)
   * 2. Generate 100 one-time prekeys
   * 3. Sign the signed prekey with identity key
   * 4. Store private keys in SecureStore
   * 5. Upload public keys to Convex
   *
   */
  async generatePreKeyBundle(
    userId: string,
    deviceId: number,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      if (!this.initialized) {
        await this.initialize();
      }

      // Set local identity for session establishment
      this.setLocalIdentity(userId, deviceId);

      // Get identity key for signing (for the specified identity type)
      const identityKey = await this.keyStorage.getIdentityKey(identityType);
      if (!identityKey) {
        throw new Error(`Identity key not found for ${identityType}`);
      }

      // Generate EC signed prekey using Signal Protocol
      const signedPreKey = await this.generateEcSignedPreKey(identityType);

      // Store EC signed prekey
      await this.keyStorage.storeEcSignedPreKey(signedPreKey, identityType);

      // Generate Kyber last-resort prekey when missing.
      // Direct local session establishment expects PQXDH material to be
      // available unless the caller explicitly removes it.
      const existingKyberPreKey = await this.keyStorage.getKyberPreKey(identityType);
      if (!existingKyberPreKey) {
        const kyberPreKey = await generateKyberLastResortPreKey(
          identityKey,
          1
        );
        await this.keyStorage.storeKyberPreKey(kyberPreKey, identityType);
      }

      // One-time prekeys are generated exclusively by the sync/replenishment
      // path; local session setup creates only a signed prekey and last-resort
      // KEM prekey.

      this.logger.breadcrumb('Prekey bundle generated', {
        category: 'E2EE',
        level: 'info',
        data: { userId, identityType },
      });
      // NOTE: Prekey upload is handled at the SignalProtocolClient layer via ConvexBackendAdapter
      // This low-level method only generates keys; upload happens in the higher layer
    } catch (error) {
      throw new EncryptionError(
        'Failed to generate prekey bundle',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Start a new session with a partner using X3DH (with optional PQXDH)
   *
   * X3DH (Extended Triple Diffie-Hellman) provides mutual authentication and forward secrecy.
   * It performs 3-4 ECDH operations and combines them using HKDF.
   *
   * PQXDH Extension: If Kyber prekey is available, adds post-quantum security via
   * CRYSTALS-Kyber-1024, providing AES-256 equivalent security against quantum computers.
   *
   * Steps:
   * 1. Verify signed prekey signature
   * 2. Perform X3DH key agreement (3-4 DH operations)
   * 3. [Optional] Add Kyber KEM for post-quantum security (PQXDH)
   * 4. Derive initial root key and chain keys using HKDF
   * 5. Initialize Double Ratchet state
   * 6. Store session in SecureStore
   *
   * CONCURRENT SAFETY: Protected by per-session lock to prevent race conditions
   * during session initialization.
   */
  async startSession(
    remoteAddress: ProtocolAddress,
    prekeyBundle: PreKeyBundle,
    recipientIdentityType: IdentityType = 'aci'
  ): Promise<void> {
    // Derive sessionId from ProtocolAddress for storage/logging
    const sessionId = ProtocolAddress.toString(remoteAddress);

    // Acquire lock for this session to ensure atomic session creation
    return await this.lock.acquire(this.getLockKey(sessionId), async () => {
      try {
        if (!this.initialized) {
          await this.initialize();
        }

        // Validate local state is initialized (via generatePreKeyBundle)
        if (this.localDeviceId === null || !this.localUserId) {
          throw new EncryptionError(
            'Local identity not set. Call generatePreKeyBundle first.',
            EncryptionErrorCode.INITIALIZATION_FAILED
          );
        }

        // Step 1: Verify signed prekey signature using identity signing key
        const { PREKEY_ALGORITHM_X25519, verifyPreKeySignature } = await import(
          '../../keys/prekey-signature'
        );
        const isValid = await verifyPreKeySignature(
          prekeyBundle.identity,
          PREKEY_ALGORITHM_X25519,
          prekeyBundle.ecSignedPreKey.keyId,
          prekeyBundle.ecSignedPreKey.publicKey,
          prekeyBundle.ecSignedPreKey.signature
        );

        if (!isValid) {
          throw new EncryptionError(
            'Invalid signed prekey signature',
            EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
          );
        }

        // Reject a known identity change before doing handshake work. The final
        // atomic commit below repeats this decision against current durable state,
        // closing the race between this pre-check and session persistence.
        const isTrusted = await this.keyStorage.isTrustedIdentity(
          remoteAddress,
          prekeyBundle.identity,
          TrustDirection.SENDING,
          recipientIdentityType
        );
        if (!isTrusted) {
          throw new UntrustedIdentityError(remoteAddress, prekeyBundle.identity);
        }

        // Step 2: Get identity key and build session via SessionBuilder
        const myIdentityKey = await this.keyStorage.getIdentityKey();
        if (!myIdentityKey) {
          throw new EncryptionError(
            'Identity key not found',
            EncryptionErrorCode.INITIALIZATION_FAILED
          );
        }

        // Create local ProtocolAddress from class fields
        const localProtocolAddress = ProtocolAddress.create(this.localUserId, this.localDeviceId);

        const builderResult = await SessionBuilder.buildInitiatorSession({
          localAddress: localProtocolAddress,
          remoteAddress, // Already a ProtocolAddress
          identityKeyPair: myIdentityKey,
          prekeyBundle,
          recipientIdentityType,
          protocolStrategy: this.protocolStrategy,
          logger: this.logger,
        });

        const { sessionState, initialRootKeyForSPQR, usedPQXDH, usedClassicalFallback } =
          builderResult;

        // Step 3: Initialize Triple Ratchet (SPQR). PQXDH sessions always require SPQR v1.
        if (usedPQXDH && !initialRootKeyForSPQR) {
          throw new EncryptionError(
            'PQXDH session missing Triple Ratchet root material',
            EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
            {
              operation: 'establishSession',
              role: 'initiator',
              usedPQXDH,
              usedClassicalFallback: !!usedClassicalFallback,
              hasInitialRootKeyForSPQR: !!initialRootKeyForSPQR,
            }
          );
        }

        if (!usedPQXDH && !usedClassicalFallback) {
          throw new EncryptionError(
            'Non-PQXDH session requires explicit classical compatibility fallback',
            EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
            {
              operation: 'establishSession',
              role: 'initiator',
              usedPQXDH,
              usedClassicalFallback: !!usedClassicalFallback,
            }
          );
        }

        if (usedPQXDH && initialRootKeyForSPQR) {
          this.logger.breadcrumb('Initializing Triple Ratchet (SPQR) for post-quantum security', {
            category: 'E2EE',
            level: 'info',
            data: { sessionId, operation: 'triple-ratchet-init' },
          });

          try {
            // Resolve SCKA mode from protocol strategy
            const sckaMode = resolveSCKAMode(this.protocolStrategy);

            // SPQR Bootstrap (Section 3.10): Generate initial Kyber-768 key pair for Alice
            // IMPORTANT: SPQR uses ML-KEM-768 (not 1024), separate from PQXDH's Kyber-1024
            // Alice needs to send her public key in the first message so Bob can encapsulate to her
            const { generateKyber768KeyPair, bytesToBase64 } = await import('../crypto');
            const initialKyberKeyPair = await generateKyber768KeyPair();
            const ourKyberPrivateKey = bytesToBase64(initialKyberKeyPair.privateKey);
            const ourKyberPublicKey = bytesToBase64(initialKyberKeyPair.publicKey);

            this.logger.debug('SPQR bootstrap: Generated initial Kyber-768 key pair (initiator)', {
              category: 'E2EE',
              data: {
                operation: 'triple-ratchet-init',
                publicKeyPreview: ourKyberPublicKey.substring(0, 30) + '...',
              },
            });

            // Initialize SPQR state for Alice (A2B direction) using original SK
            const spqrState = await SPQR.initializeSPQR({
              mode: sckaMode,
              initialRootKey: initialRootKeyForSPQR, // ✅ Original SK (same as Bob will use)
              direction: 'A2B',
              ourKyberPrivateKey, // ✅ Store private key for future decapsulation
              theirKyberPublicKey: null, // Will be received in Bob's first reply
              spqrLimits: this.protocolStrategy?.spqrLimits,
            });

            // SPQR Bootstrap: flag that first spqrSend() should generate keypair
            // spqrSend() handles lazy KEM — no pending fields needed
            spqrState.needsSendRatchet = true;

            // Add Triple Ratchet to session BEFORE zeroing the key
            // This ensures we only zero after successful initialization
            sessionState.tripleRatchet = {
              spqrState: spqrState,
              enabled: true,
              enabledAt: Date.now(),
            };

            this.logger.breadcrumb('Triple Ratchet initialized with original SK', {
              category: 'E2EE',
              level: 'info',
              data: { sessionId, spqrEpoch: spqrState.epoch, needsSendRatchet: true },
            });
          } catch (spqrError) {
            // SPQR initialization failed - this is a critical error
            // Log and propagate the error rather than silently degrading
            this.logger.error('Triple Ratchet (SPQR) initialization failed', {
              category: 'E2EE',
              data: {
                sessionId,
                error: spqrError instanceof Error ? spqrError.message : String(spqrError),
              },
            });
            throw new EncryptionError(
              'Failed to initialize Triple Ratchet (SPQR)',
              EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
              { originalError: spqrError as Error }
            );
          } finally {
            // Securely zero preserved SK after use (Signal Protocol Section 8.1)
            // Always zero the key whether initialization succeeded or failed
            CryptoUtils.secureZeroBytes(initialRootKeyForSPQR);
          }
        }

        // Steps 4-5: Pin/match the remote TOFU identity and persist the new
        // session at one durable commit point. A racing identity rotation must
        // fail closed without leaving either half of the state visible.
        try {
          await this.keyStorage.commitSessionTrust({
            address: remoteAddress,
            record: {
              currentSession: sessionState,
              archivedSessions: {},
              version: CURRENT_SESSION_RECORD_VERSION,
            },
            contactIdentity: prekeyBundle.identity,
            contactIdentityType: recipientIdentityType,
            localIdentityType: sessionState.localIdentityType,
          });
        } catch (storageError) {
          if (storageError instanceof EncryptionError) {
            throw storageError;
          }
          throw new EncryptionError(
            `Failed to persist session trust for ${ProtocolAddress.toString(remoteAddress)}`,
            EncryptionErrorCode.KEY_STORAGE_ERROR,
            { originalError: storageError as Error }
          );
        }

        this.logger.breadcrumb('Session established', {
          category: 'E2EE',
          level: 'info',
          data: { sessionId },
        });
      } catch (error) {
        this.logger.error('Session establishment failed', error, {
          category: 'E2EE',
          data: { sessionId },
        });
        if (error instanceof EncryptionError) {
          throw error;
        }
        throw new EncryptionError(
          `Failed to start session for ${ProtocolAddress.toString(remoteAddress)}`,
          EncryptionErrorCode.INVALID_PREKEY_BUNDLE,
          { originalError: error as Error }
        );
      }
    });
  }

  /**
   * Perform X3DH key exchange as responder (with optional PQXDH extension)
   *
   * Implements Signal Protocol Section 3.3 RatchetInitBob (with PQXDH extension).
   * Delegates to SessionBuilder for key agreement and session creation.
   *
   * Session Identification:
   * - Sessions are LOOKED UP by ProtocolAddress (userId:deviceId)
   * - Session STATES are IDENTIFIED by baseKey (initiator's ephemeral public key)
   *
   * @param remoteAddress Partner's ProtocolAddress (Alice)
   * @param prekeyMessage Alice's PreKeyMessage containing her keys
   * @returns Session state compatible with Alice's session
   *
   * @see https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol - X3DH protocol (Bob responder)
   * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol - PQXDH extension
   * @see https://signal.org/docs/specifications/doubleratchet/#initialization - RatchetInitBob
   */
  private async performX3DHResponder(
    remoteAddress: ProtocolAddress,
    prekeyMessage: PreKeyMessage
  ): Promise<SessionState> {
    this.logger.breadcrumb('X3DH as responder (Bob)', {
      category: 'E2EE',
      level: 'info',
      data: {
        remoteAddress: ProtocolAddress.toString(remoteAddress),
        operation: 'x3dh',
        role: 'responder',
      },
    });

    // Step 1: Select the explicit recipient identity namespace. The wire value
    // is duplicated inside the MAC-authenticated SignalProtocolMessage, so key-ID
    // collisions cannot redirect an ACI message into the PNI store or vice versa.
    const usedSignedPreKeyId = prekeyMessage.usedSignedPreKeyId;
    const identityType = prekeyMessage.recipientIdentityType;
    const mySignedPreKey = await this.keyStorage.getEcSignedPreKey(
      usedSignedPreKeyId,
      identityType
    );

    // Step 2: Get Bob's identity key (using resolved identity type)
    const myIdentityKey = await this.keyStorage.getIdentityKey(identityType);
    if (!myIdentityKey) {
      throw new EncryptionError(
        `Identity key not found for ${identityType}`,
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    // Validate identity DH key pair integrity before X3DH
    // This catches storage corruption that causes MAC verification failures
    CryptoUtils.validateX25519KeyPair(
      myIdentityKey.dhKey.publicKey,
      myIdentityKey.dhKey.privateKey,
      'identityKey:dhKey'
    );

    // Step 3: Validate the signed prekey in the selected namespace.
    // Per X3DH Spec Section 4.4 - Bob should keep old signed prekeys for ~30 days
    // to handle in-flight messages that used the old key.
    if (!mySignedPreKey) {
      // CRITICAL: If Alice used a signed prekey we no longer have, the DH3 computation
      // will fail because we can't compute DH(SPK_priv, alice_ephemeral_pub).
      //
      // This can happen when:
      // 1. Bob rotated his signed prekey AND the old one expired past the grace period
      // 2. Alice cached a very old prekey bundle
      //
      // The correct behavior is to FAIL and trigger a retry request, which will:
      // 1. Ask Alice to re-encrypt with a fresh prekey bundle
      // 2. Alice fetches Bob's current signed prekey and re-establishes session
      //
      // @see X3DH Spec Section 4.4 - signed prekey grace period handling
      this.logger.warn('Signed prekey not found in selected identity store', {
        category: 'E2EE',
        data: {
          requestedKeyId: usedSignedPreKeyId,
          identityType,
          operation: 'x3dh-responder',
        },
      });

      throw new EncryptionError(
        `Signed prekey not found in ${identityType} store (keyId=${usedSignedPreKeyId}) - sender may have stale prekey bundle. ` +
          'This typically happens when signed prekey was rotated and old one expired. ' +
          'A retry with fresh bundle is needed.',
        EncryptionErrorCode.PREKEY_NOT_FOUND,
        { signedPreKeyId: usedSignedPreKeyId }
      );
    }

    // Validate signed prekey pair integrity before X3DH
    // This catches storage corruption that causes MAC verification failures
    CryptoUtils.validateX25519KeyPair(
      mySignedPreKey.publicKey,
      mySignedPreKey.privateKey,
      `signedPreKey:${usedSignedPreKeyId}`
    );

    // Step 4: Get Bob's one-time prekey if Alice used one
    let myOneTimePreKey: EcOneTimePreKey | null = null;
    if (prekeyMessage.usedOneTimePreKeyId !== undefined) {
      const oneTimePreKeys = await this.keyStorage.getEcOneTimePreKeys(identityType);
      myOneTimePreKey =
        oneTimePreKeys.find(
          (pk: EcOneTimePreKey) => pk.keyId === prekeyMessage.usedOneTimePreKeyId
        ) || null;

      if (!myOneTimePreKey) {
        // CRITICAL: If Alice used an EC one-time prekey, Bob MUST have it for X3DH.
        // If Bob doesn't have it, the IKM will be different and decryption will fail.
        //
        // This happens when:
        // 1. Bob reinstalled the app (local SQLite wiped, server had stale prekeys)
        // 2. Alice fetched a stale prekey bundle before Bob's re-registration cleared them
        //
        // The correct behavior is to FAIL and trigger a retry request, which will:
        // 1. Ask Alice to re-encrypt with a fresh prekey bundle
        // 2. After the server-side fix, the fresh bundle won't have stale prekeys
        //
        // Note: While X3DH spec Section 3.3 allows optional one-time prekeys, if Alice
        // explicitly included one, Bob must have it - otherwise the IKM will differ.
        //
        // @see X3DH Spec Section 3.2 - one-time prekeys provide forward secrecy for first message
        throw new EncryptionError(
          'EC one-time prekey not found - sender may have stale prekey bundle. ' +
            'This typically happens after app reinstall. A retry with fresh bundle is needed.',
          EncryptionErrorCode.PREKEY_NOT_FOUND,
          { ecPreKeyId: prekeyMessage.usedOneTimePreKeyId }
        );
      }

      // Validate one-time prekey pair integrity before X3DH
      // This catches storage corruption that causes MAC verification failures
      CryptoUtils.validateX25519KeyPair(
        myOneTimePreKey.publicKey,
        myOneTimePreKey.privateKey,
        `oneTimePreKey:${prekeyMessage.usedOneTimePreKeyId}`
      );
    }

    // Step 5: Get Bob's Kyber prekey if Alice used one (for PQXDH)
    let myKyberPreKey: KyberPreKey | null = null;
    if (prekeyMessage.usedKyberPreKeyId !== undefined && prekeyMessage.kyberCiphertext) {
      const retrievedKyberPreKey = await this.keyStorage.getKyberPreKey(identityType);

      if (!retrievedKyberPreKey) {
        this.logger.warn('Kyber prekey not found for PQXDH message; aborting session', {
          category: 'E2EE',
          data: { kyberPreKeyId: prekeyMessage.usedKyberPreKeyId },
        });
      } else {
        // BUG #7 FIX: Validate that the Kyber prekey ID matches what Alice used
        // If IDs don't match, Alice encapsulated to a DIFFERENT key than we have locally,
        // which means decapsulation would produce wrong shared secret → MAC failure.
        // Instead of silently proceeding to fail, detect this early and trigger retry.
        const keyIdMatches = prekeyMessage.usedKyberPreKeyId === retrievedKyberPreKey.keyId;

        this.logger.info('Bob X3DH: Kyber prekey lookup (Bug #7 diagnostic)', {
          category: 'E2EE',
          data: {
            usedKyberPreKeyIdFromMessage: prekeyMessage.usedKyberPreKeyId,
            foundKyberKeyId: retrievedKyberPreKey.keyId,
            keyIdMatches,
            myKyberPreKeyPub: retrievedKyberPreKey.publicKey.substring(0, 32),
          },
        });

        if (!keyIdMatches) {
          // BUG #7 FIX: Kyber prekey ID mismatch - sender has stale bundle
          // Per PQXDH §4.13: Identifier collisions cause MAC verification failures.
          // Instead of proceeding and failing at MAC verification, throw early so the
          // retry mechanism (Bug #3/#4) can request sender to fetch fresh bundle.
          this.logger.warn('Kyber prekey ID mismatch - sender has stale bundle', {
            category: 'E2EE',
            data: {
              operation: 'x3dh-responder',
              senderUsedKeyId: prekeyMessage.usedKyberPreKeyId,
              localKeyId: retrievedKyberPreKey.keyId,
              reason: 'Alice encapsulated to old Kyber key, Bob cannot decapsulate correctly',
            },
          });

          throw new EncryptionError(
            `Kyber prekey ID mismatch: sender used keyId=${prekeyMessage.usedKyberPreKeyId}, ` +
              `but local storage has keyId=${retrievedKyberPreKey.keyId}. ` +
              'Sender may have stale prekey bundle. A retry with fresh bundle is needed.',
            EncryptionErrorCode.PREKEY_NOT_FOUND,
            {
              kyberPreKeyId: prekeyMessage.usedKyberPreKeyId,
              localKyberKeyId: retrievedKyberPreKey.keyId,
            }
          );
        }

        myKyberPreKey = retrievedKyberPreKey;
      }
    }

    // Step 5b: Get Bob's KEM one-time prekey if Alice used one (for per-session post-quantum forward secrecy)
    let myKemOneTimePreKey: KemOneTimePreKey | null = null;

    // Diagnostic: Log KEM one-time fields from received PreKeyMessage for debugging IKM mismatch
    this.logger.debug('Received PreKeyMessage KEM one-time fields', {
      category: 'E2EE',
      data: {
        operation: 'x3dh-responder-kem-check',
        usedKemOneTimePreKeyId: prekeyMessage.usedKemOneTimePreKeyId,
        typeofKeyId: typeof prekeyMessage.usedKemOneTimePreKeyId,
        hasKemCiphertext: !!prekeyMessage.kemOneTimePreKeyCiphertext,
        kemCiphertextLen: prekeyMessage.kemOneTimePreKeyCiphertext?.length,
        conditionResult:
          prekeyMessage.usedKemOneTimePreKeyId !== undefined &&
          !!prekeyMessage.kemOneTimePreKeyCiphertext,
      },
    });

    if (
      prekeyMessage.usedKemOneTimePreKeyId !== undefined &&
      prekeyMessage.kemOneTimePreKeyCiphertext
    ) {
      myKemOneTimePreKey = await this.keyStorage.getKemOneTimePreKey(
        prekeyMessage.usedKemOneTimePreKeyId,
        identityType
      );
      if (!myKemOneTimePreKey) {
        // CRITICAL: If Alice used a KEM one-time prekey, Bob MUST have it for decapsulation.
        // If Bob doesn't have it, the IKM will be different and decryption will fail.
        //
        // This happens when:
        // 1. Bob reinstalled the app (local SQLite wiped, server had stale prekeys)
        // 2. Alice fetched a stale prekey bundle before Bob's re-registration cleared them
        //
        // The correct behavior is to FAIL and trigger a retry request, which will:
        // 1. Ask Alice to re-encrypt with a fresh prekey bundle
        // 2. After the server-side fix, the fresh bundle won't have stale prekeys
        //
        // @see X3DH Spec Section 3.2 - one-time prekeys provide forward secrecy for first message
        throw new EncryptionError(
          'KEM one-time prekey not found - sender may have stale prekey bundle. ' +
            'This typically happens after app reinstall. A retry with fresh bundle is needed.',
          EncryptionErrorCode.PREKEY_NOT_FOUND,
          { kemPreKeyId: prekeyMessage.usedKemOneTimePreKeyId }
        );
      }
    }

    // Step 6: Create local address for session builder
    if (!this.localUserId || this.localDeviceId === null) {
      throw new EncryptionError(
        'Local user ID or device ID not set. Call generatePreKeyBundle first.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
    const localAddressUserId =
      identityType === 'pni' ? `pni-${this.localUserId}` : this.localUserId;
    const localAddress = ProtocolAddress.create(localAddressUserId, this.localDeviceId);

    // Step 7: Build session via SessionBuilder (handles all key agreement)
    const builderResult = await SessionBuilder.buildResponderSession({
      localAddress,
      remoteAddress,
      identityKeyPair: myIdentityKey,
      prekeyMessage,
      ecSignedPreKey: mySignedPreKey,
      ecOneTimePreKey: myOneTimePreKey,
      kemLastResortPreKey: myKyberPreKey,
      kemOneTimePreKey: myKemOneTimePreKey,
      protocolStrategy: this.protocolStrategy,
      logger: this.logger,
    });

    const { sessionState, usedPQXDH, initialRootKeyForSPQR, usedClassicalFallback } = builderResult;

    this.logger.debug('performX3DHResponder: Received builder result', {
      category: 'E2EE',
      data: {
        operation: 'x3dh-responder',
        usedPQXDH,
        usedClassicalFallback: !!usedClassicalFallback,
        hasInitialRootKeyForSPQR: !!initialRootKeyForSPQR,
        initialRootKeyLength: initialRootKeyForSPQR?.length,
      },
    });

    // Defer one-time prekey deletion until the first successful decryption so a
    // corrupted inner message does not make recovery impossible.
    if (myOneTimePreKey || myKemOneTimePreKey) {
      sessionState.pendingPreKeyDeletion = {
        oneTimePreKeyId: myOneTimePreKey?.keyId,
        kemOneTimePreKeyId: myKemOneTimePreKey?.keyId,
        identityType,
      };
      this.logger.debug('Deferred prekey deletion until first successful decryption', {
        category: 'E2EE',
        data: { ecKeyId: myOneTimePreKey?.keyId, kemKeyId: myKemOneTimePreKey?.keyId },
      });
    }

    // Step 8: Initialize Triple Ratchet (SPQR). PQXDH sessions always require SPQR v1.
    if (usedPQXDH && !initialRootKeyForSPQR) {
      throw new EncryptionError(
        'PQXDH session missing Triple Ratchet root material',
        EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
        {
          operation: 'performX3DHResponder',
          role: 'responder',
          usedPQXDH,
          usedClassicalFallback: !!usedClassicalFallback,
          hasInitialRootKeyForSPQR: !!initialRootKeyForSPQR,
        }
      );
    }

    if (!usedPQXDH && !usedClassicalFallback) {
      throw new EncryptionError(
        'Non-PQXDH session requires explicit classical compatibility fallback',
        EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
        {
          operation: 'performX3DHResponder',
          role: 'responder',
          usedPQXDH,
          usedClassicalFallback: !!usedClassicalFallback,
        }
      );
    }

    if (usedPQXDH && initialRootKeyForSPQR) {
      this.logger.breadcrumb('Initializing Triple Ratchet (SPQR) as responder', {
        category: 'E2EE',
        level: 'info',
        data: {
          baseKey: sessionState.baseKey.substring(0, 20),
          operation: 'triple-ratchet-init',
          role: 'responder',
        },
      });

      try {
        // Resolve SCKA mode from protocol strategy
        const sckaMode = resolveSCKAMode(this.protocolStrategy);

        // SPQR Bootstrap (Section 3.10): Generate initial Kyber-768 key pair for Bob
        // IMPORTANT: SPQR uses ML-KEM-768 (not 1024), separate from PQXDH's Kyber-1024
        // Bob needs to send his public key in his first reply so Alice can encapsulate to him
        const { generateKyber768KeyPair, bytesToBase64 } = await import('../crypto');
        const initialKyberKeyPair = await generateKyber768KeyPair();
        const ourKyberPrivateKey = bytesToBase64(initialKyberKeyPair.privateKey);
        const ourKyberPublicKey = bytesToBase64(initialKyberKeyPair.publicKey);

        this.logger.debug('SPQR bootstrap: Generated initial Kyber-768 key pair (responder)', {
          category: 'E2EE',
          data: {
            operation: 'triple-ratchet-init',
            publicKeyPreview: ourKyberPublicKey.substring(0, 30) + '...',
          },
        });

        // Initialize SPQR state for Bob (B2A direction)
        // Per Signal Protocol Section 5.4 - Initialize epoch 0 chains only (no ratchet step yet)
        // theirKyberPublicKey starts null — spqrRecv will populate it when decrypting
        // Alice's first message (the pqRatchet field contains her Kyber public key)
        const spqrState = await SPQR.initializeSPQR({
          mode: sckaMode,
          initialRootKey: initialRootKeyForSPQR,
          direction: 'B2A',
          ourKyberPrivateKey, // ✅ Store private key for future decapsulation
          theirKyberPublicKey: null, // Populated by spqrRecv during first decrypt
          spqrLimits: this.protocolStrategy?.spqrLimits,
        });

        // SPQR Bootstrap: flag that first spqrSend() should generate keypair
        // spqrSend() handles lazy KEM — no pending fields needed
        spqrState.needsSendRatchet = true;

        // Add Triple Ratchet to session BEFORE zeroing the key
        // This ensures we only zero after successful initialization
        sessionState.tripleRatchet = {
          spqrState: spqrState,
          enabled: true,
          enabledAt: Date.now(),
        };

        this.logger.breadcrumb('Triple Ratchet initialized (responder)', {
          category: 'E2EE',
          level: 'info',
          data: {
            baseKey: sessionState.baseKey.substring(0, 20),
            spqrEpoch: spqrState.epoch,
            role: 'responder',
            needsSendRatchet: true,
            hasTheirKyberPublicKey: false, // Populated by spqrRecv during first decrypt
          },
        });
      } catch (spqrError) {
        // SPQR initialization failed - this is a critical error
        // Log and propagate the error rather than silently degrading
        this.logger.error('Triple Ratchet (SPQR) initialization failed (responder)', {
          category: 'E2EE',
          data: {
            baseKey: sessionState.baseKey.substring(0, 20),
            error: spqrError instanceof Error ? spqrError.message : String(spqrError),
          },
        });
        throw new EncryptionError(
          'Failed to initialize Triple Ratchet (SPQR) as responder',
          EncryptionErrorCode.TRIPLE_RATCHET_REQUIRED,
          { originalError: spqrError as Error }
        );
      } finally {
        // Securely zero preserved SK after use (Signal Protocol Section 8.1)
        // Always zero the key whether initialization succeeded or failed
        CryptoUtils.secureZeroBytes(initialRootKeyForSPQR);
      }
    }

    this.logger.breadcrumb('Responder session established (lazy init)', {
      category: 'E2EE',
      level: 'info',
      data: {
        baseKey: sessionState.baseKey.substring(0, 20),
        operation: 'x3dh',
        role: 'responder',
        usedPQXDH,
        lazyInit: true,
        // Chain keys are undefined until first DHRatchet during decrypt
        CKsSet: sessionState.CKs !== undefined,
        CKrSet: sessionState.CKr !== undefined,
      },
    });

    return sessionState;
  }

  /**
   * Clean up expired message keys from receiverChains
   *
   * Signal Protocol Section 8.4 -
   * "To avoid excessive storage, parties SHOULD delete keys for messages
   * that have been received or that have been skipped for too long.
   * A recommended policy is to delete message keys more than one week old."
   *
   * @param session Session state to clean
   * @param config Double Ratchet configuration with maxMessageKeyAge
   */
  private cleanupExpiredMessageKeys(
    session: SessionState,
    config: DoubleRatchetConfig = DEFAULT_RATCHET_CONFIG
  ): void {
    // Can't extract ratchet state if session not fully initialized
    if (!session.DHs || !session.DHr) {
      return; // Skip cleanup for uninitialized sessions
    }

    // Extract ratchet state for delegation
    const ratchetState = this.extractRatchetState(session);

    // Delegate to module (handles secure zeroing and deletion)
    moduleCleanupExpiredKeys(
      ratchetState,
      {
        maxSkippedMessages: config.maxSkippedMessages,
        maxMessageKeysStored: config.maxMessageKeysStored,
        maxMessageKeyAge: config.maxMessageKeyAge,
        kyberRefreshInterval: config.kyberRefreshInterval,
      },
      this.logger
    );

    // Apply updated receiverChains and processedChains back to session
    session.receiverChains = ratchetState.receiverChains;
    session.processedChains = ratchetState.processedChains;
  }

  // NOTE: shouldRefreshKyber() and refreshKyberKeys() removed - superseded by Triple Ratchet
  // Triple Ratchet (Section 6) provides complete SPQR with automatic Kyber refresh.

  /**
   * Encrypt a message using Full Double Ratchet
   *
   * Delegates to SessionCipher for the actual encryption.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param plaintext - Message to encrypt
   * @see Signal Protocol Specification Section 3.4 - The Double Ratchet - RatchetEncrypt
   */
  async encrypt(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext> {
    return this.getSessionCipher().encrypt(remoteAddress, plaintext);
  }

  /**
   * Decrypt a message using Full Double Ratchet
   *
   * Delegates to SessionCipher for the actual decryption.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param ciphertext - Message to decrypt
   * @see Signal Protocol Specification Section 3.5 - The Double Ratchet - RatchetDecrypt
   */
  async decrypt(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string> {
    return this.getSessionCipher().decrypt(remoteAddress, ciphertext);
  }

  /**
   * Check if session exists for session
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @returns true if session exists, false otherwise
   */
  async hasSession(remoteAddress: ProtocolAddress): Promise<boolean> {
    const record = await this.keyStorage.getSessionRecord(remoteAddress);
    return record?.currentSession !== null && record?.currentSession !== undefined;
  }

  /**
   * Get the session record for a remote address.
   *
   * Used by SESAME to sync sessions after PreKeyMessage decryption.
   * Per SESAME specification, after the responder decrypts a PreKeyMessage,
   * the session needs to be synced from KeyStorage to DeviceRecord.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @returns The session record, or null if no session exists
   */
  async getSession(remoteAddress: ProtocolAddress): Promise<SessionRecord | null> {
    return this.keyStorage.getSessionRecord(remoteAddress);
  }

  /**
   * Rotate EC signed prekey (LOCAL STORAGE ONLY)
   *
   * Per Signal Protocol architecture, the protocol layer handles local key
   * generation and storage. Server synchronization is handled at the
   * application layer via SignalProtocolClient.rotateEcSignedPreKey().
   *
   * This method (local only):
   * 1. Generates new EC signed prekey
   * 2. Signs with identity key
   * 3. Stores locally (replaces previous)
   *
   * Full lifecycle (handled by SignalProtocolClient):
   * 4. Upload new prekey to server
   * 5. Mark old prekey as deprecated (grace period for in-flight messages)
   * 6. Delete deprecated prekeys after ~1 week
   *
   * @param userId - User ID for logging purposes
   *
   * @see SignalProtocolClient.rotateEcSignedPreKey() for full rotation with server sync
   * @see https://signal.org/docs/specifications/x3dh/#publishing-keys
   */
  async rotateEcSignedPreKey(userId: string, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      // Get identity key for signing (for the specified identity type)
      const identityKey = await this.keyStorage.getIdentityKey(identityType);
      if (!identityKey) {
        throw new Error(`Identity key not found (${identityType})`);
      }

      // Generate new EC signed prekey
      const newSignedPreKey = await this.generateEcSignedPreKey(identityType);

      // Store new EC signed prekey locally (server upload handled by SignalProtocolClient)
      await this.keyStorage.storeEcSignedPreKey(newSignedPreKey, identityType);

      this.logger.breadcrumb('EC signed prekey rotated (local)', {
        category: 'E2EE',
        level: 'info',
        data: { userId, identityType, operation: 'key_rotation' },
      });
    } catch (error) {
      throw new EncryptionError(
        'Failed to rotate EC signed prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Rotate Kyber prekey (LOCAL STORAGE ONLY)
   *
   * Per Signal Protocol architecture, the protocol layer handles local key
   * generation and storage. Server synchronization is handled at the
   * application layer via SignalProtocolClient.rotateKyberPreKey().
   *
   * This method (local only):
   * 1. Generates new Kyber-1024 keypair
   * 2. Signs with identity key
   * 3. Stores locally (replaces previous)
   *
   * Full lifecycle (handled by SignalProtocolClient):
   * 4. Upload new Kyber prekey to server
   * 5. Mark old Kyber prekey as deprecated (grace period for in-flight messages)
   * 6. Delete deprecated Kyber prekeys after ~1 week
   *
   * Uses incrementing key IDs to enable mismatch detection during rotation.
   *
   * @param userId - User ID for logging purposes
   *
   * @see SignalProtocolClient.rotateKyberPreKey() for full rotation with server sync
   * @see https://signal.org/docs/specifications/pqxdh/#key-rotation
   */
  async rotateKyberPreKey(userId: string, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      // Get identity key for signing (for the specified identity type)
      const identityKey = await this.keyStorage.getIdentityKey(identityType);
      if (!identityKey) {
        throw new Error(`Identity key not found (${identityType})`);
      }

      // Get current Kyber prekey's ID and increment for the new one
      // This ensures unique IDs for mismatch detection during key rotation
      const currentKyber = await this.keyStorage.getKyberPreKey(identityType);
      const nextKeyId = (currentKyber?.keyId ?? 0) + 1;

      const newKyberPreKey = await generateKyberLastResortPreKey(
        identityKey,
        nextKeyId
      );

      // Store new Kyber prekey locally (server upload handled by SignalProtocolClient)
      await this.keyStorage.storeKyberPreKey(newKyberPreKey, identityType);

      this.logger.breadcrumb('Kyber prekey rotated (local)', {
        category: 'E2EE',
        level: 'info',
        data: { userId, identityType, operation: 'pqxdh_rotation' },
      });
    } catch (error) {
      throw new EncryptionError(
        'Failed to rotate Kyber prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Clean up expired message keys for a session
   *
   * Signal Protocol Section 8.4 - Deletion of Old Skipped Message Keys
   * "To avoid excessive storage, parties SHOULD delete keys for messages that
   * have been received or that have been skipped for too long. A recommended
   * policy is to delete message keys more than one week old."
   *
   * This method explicitly triggers cleanup of expired message keys.
   * Note: Cleanup also happens automatically during encrypt/decrypt operations.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   */
  async cleanupExpiredKeys(remoteAddress: ProtocolAddress): Promise<void> {
    const sessionId = ProtocolAddress.toString(remoteAddress);
    try {
      const record = await this.keyStorage.getSessionRecord(remoteAddress);
      // Work on a candidate copy so an in-memory adapter cannot observe partial
      // cleanup if validation or durable persistence fails.
      const candidateRecord = record ? CryptoUtils.cloneProtocolState(record) : null;
      const session = candidateRecord?.currentSession;
      if (!session) {
        // Session doesn't exist - nothing to clean up
        return;
      }

      // Run cleanup
      this.cleanupExpiredMessageKeys(session);

      // Save the cleaned session, preserving existing record fields
      await this.keyStorage.storeSessionRecord(remoteAddress, {
        ...candidateRecord,
        currentSession: session,
      });

      this.logger.breadcrumb('Expired message keys cleaned up', {
        category: 'E2EE',
        data: {
          sessionId,
          operation: 'cleanup_expired_keys',
        },
      });
    } catch (error) {
      throw new EncryptionError(
        'Failed to cleanup expired keys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get identity public key
   */
  async getIdentityPublicKey(): Promise<PublicKey> {
    const identityKey = await this.keyStorage.getIdentityKey();
    if (!identityKey) {
      throw new EncryptionError('Identity key not found', EncryptionErrorCode.KEY_STORAGE_ERROR);
    }
    return identityKey.signingKey.publicKey;
  }

  // ========================================================================
  // KEY GENERATION
  // ========================================================================

  /**
   * Generate identity key pair with both DH and signing keys
   *
   * Signal Protocol needs:
   * - DH key (ECDH) for X3DH key exchange (DH1 operation)
   * - Signing key (Ed25519) for signing prekeys
   *
   * @see https://signal.org/docs/specifications/x3dh/#keys - Identity key format (IKA, IKB)
   * @see https://signal.org/docs/specifications/x3dh/#publishing-keys - Identity key usage
   */
  private async generateIdentityKey(): Promise<IdentityKeyPair> {
    // Delegate to keys module
    return generateIdentityKeyPair();
  }

  /**
   * Generate EC signed prekey using ECDH, then sign it with identity signing key
   *
   * @see https://signal.org/docs/specifications/x3dh/#keys - Signed prekey format (SPK)
   * @see https://signal.org/docs/specifications/x3dh/#publishing-keys - Signed prekey generation and rotation
   */
  private async generateEcSignedPreKey(
    identityType: IdentityType = 'aci'
  ): Promise<EcSignedPreKey> {
    // Get identity key for signing (for the specified identity type)
    const identityKey = await this.keyStorage.getIdentityKey(identityType);
    if (!identityKey) {
      throw new Error(`Identity key not found for signing prekey (${identityType})`);
    }

    // Delegate to keys module
    return generateEcSignedPreKey(identityKey);
  }

  /**
   * Generate EC one-time prekeys using ECDH
   *
   * @see https://signal.org/docs/specifications/x3dh/#keys - One-time prekey format (OPK)
   * @see https://signal.org/docs/specifications/x3dh/#publishing-keys - One-time prekey bundle
   */
  private async generateEcOneTimePreKeys(count: number): Promise<EcOneTimePreKey[]> {
    // Delegate to keys module (startId = 0 matches original behavior)
    return generateEcOneTimePreKeys(count, 0);
  }
}
// Singleton pattern removed - use direct instantiation (new SignalProtocolManager())
// or use SignalProtocolClient as the public API wrapper
